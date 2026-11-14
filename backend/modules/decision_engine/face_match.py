"""Server-side face identity: compare the liveness session's reference image with the enrolled photo.

Enrolled photo: s3://$FACE_REFERENCE_BUCKET/<person_id>.jpg (private bucket, 7-day lifecycle).
Both images exist only in memory for the CompareFaces call. Nothing here stores, logs or returns image bytes.
The Lambda role has s3:GetObject on that bucket only (no ListBucket), so a missing photo comes back as
AccessDenied rather than NoSuchKey; both mean "no enrolled reference".
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Optional

from botocore.exceptions import BotoCoreError, ClientError

MATCH, NO_MATCH, NO_REFERENCE, NO_FACE, ERROR = "MATCH", "NO_MATCH", "NO_REFERENCE", "NO_FACE", "ERROR"
SAFE_PERSON_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
NOT_FOUND_CODES = {"NoSuchKey", "AccessDenied", "404", "403", "NotFound"}
MAX_REFERENCE_BYTES = 5_000_000


@dataclass(frozen=True)
class FaceCheck:
    status: str                         # MATCH / NO_MATCH / NO_REFERENCE / NO_FACE / ERROR
    similarity: Optional[float] = None  # set for MATCH and NO_MATCH
    note: Optional[str] = None

    @property
    def compared(self) -> bool:
        return self.status in (MATCH, NO_MATCH)


class ServerFaceMatcher:
    def __init__(self, rekognition=None, s3=None, bucket: Optional[str] = None):
        self._rekognition, self._s3 = rekognition, s3
        self._bucket = bucket

    @property
    def bucket(self) -> Optional[str]:
        return self._bucket if self._bucket is not None else os.environ.get("FACE_REFERENCE_BUCKET") or None

    def _client(self, name: str):
        import boto3
        from botocore.config import Config

        return boto3.client(name, region_name=os.environ.get("AWS_REGION", "us-east-1"),
                            config=Config(connect_timeout=2, read_timeout=5, retries={"max_attempts": 2, "mode": "standard"}))

    @property
    def rekognition(self):
        if self._rekognition is None:
            self._rekognition = self._client("rekognition")
        return self._rekognition

    @property
    def s3(self):
        if self._s3 is None:
            self._s3 = self._client("s3")
        return self._s3

    def _reference(self, person_id: str) -> tuple[Optional[bytes], Optional[FaceCheck]]:
        if not self.bucket:
            return None, FaceCheck(NO_REFERENCE, note="face reference bucket is not configured")
        if not SAFE_PERSON_ID.match(person_id or ""):
            return None, FaceCheck(NO_REFERENCE, note="identity has no usable reference key")
        try:
            obj = self.s3.get_object(Bucket=self.bucket, Key=f"{person_id}.jpg")
            data = obj["Body"].read(MAX_REFERENCE_BYTES + 1)
        except ClientError as e:
            code = str(e.response.get("Error", {}).get("Code", ""))
            if code in NOT_FOUND_CODES:
                return None, FaceCheck(NO_REFERENCE, note=f"no enrolled reference photo for {person_id}")
            return None, FaceCheck(ERROR, note=f"reference photo unavailable ({code or 'ClientError'})")
        except BotoCoreError as e:
            return None, FaceCheck(ERROR, note=f"reference photo unavailable ({type(e).__name__})")
        if not data or len(data) > MAX_REFERENCE_BYTES:
            return None, FaceCheck(NO_REFERENCE, note=f"reference photo for {person_id} is empty or too large")
        return data, None

    def match(self, person_id: str, probe: bytes) -> FaceCheck:
        reference, problem = self._reference(person_id)
        if problem:
            return problem
        try:
            r = self.rekognition.compare_faces(SourceImage={"Bytes": probe}, TargetImage={"Bytes": reference},
                                               SimilarityThreshold=0)
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "ClientError")
            if code == "InvalidParameterException":  # Rekognition: no face detected in one of the images
                return FaceCheck(NO_FACE, note="no face found in the live or the enrolled image")
            return FaceCheck(ERROR, note=f"face comparison failed ({code})")
        except BotoCoreError as e:
            return FaceCheck(ERROR, note=f"face comparison failed ({type(e).__name__})")
        finally:
            reference = None  # noqa: F841 - drop the enrolled image bytes
        scores = [float(m["Similarity"]) for m in r.get("FaceMatches", []) if isinstance(m.get("Similarity"), (int, float))]
        if not scores:
            return FaceCheck(NO_MATCH, 0.0)
        best = max(scores)
        return FaceCheck(MATCH if best >= 80.0 else NO_MATCH, best)
