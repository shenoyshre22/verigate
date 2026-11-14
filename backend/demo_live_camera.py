"""Local-only webcam identity-recognition demo. It does not perform liveness checks."""

from __future__ import annotations

import argparse
import os
import re
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from backend.modules.face_authentication.recognition_exceptions import InvalidImageError  # noqa: E402
from backend.modules.face_recognition.embedding_provider import DeepFaceEmbeddingProvider  # noqa: E402
from backend.modules.face_recognition.errors import (  # noqa: E402
    FaceEnrollmentExists,
    FaceIdentityConfigurationError,
    FaceIdentityMultipleFaces,
    FaceIdentityNoFace,
    FaceIdentityProviderError,
    FaceIdentityStorageError,
)
from backend.modules.face_recognition.service import FaceIdentityService  # noqa: E402
from backend.modules.face_recognition.storage import SQLiteFaceEnrollmentStore  # noqa: E402
from backend.tests.face_recognition.demo_protector import TestProtector as DemoOnlyProtector  # noqa: E402


WINDOW_NAME = "VERIGATE — Face Identity Demo (No Liveness)"
TEST_ID_PATTERN = re.compile(r"TEST[A-Z0-9_-]{1,28}\Z")


def _production_environment() -> bool:
    if any(os.getenv(name) for name in (
        "AWS_LAMBDA_FUNCTION_NAME", "AWS_EXECUTION_ENV", "ECS_CONTAINER_METADATA_URI_V4", "K_SERVICE"
    )):
        return True
    return any(
        os.getenv(name, "").strip().lower() in {"production", "prod"}
        for name in ("APP_ENV", "VERIGATE_ENV", "ENVIRONMENT")
    )


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Local synthetic-test webcam recognition; this is not liveness detection."
    )
    parser.add_argument(
        "--allow-test-protector",
        action="store_true",
        help="Acknowledge isolated SQLite uses the reversible test-only XOR protector.",
    )
    parser.add_argument(
        "--synthetic-test-data-only",
        action="store_true",
        help="Confirm you will present synthetic test faces only, never a real student's face.",
    )
    return parser.parse_args()


def _show_instructions(cv2: Any, frame: Any, message: str) -> Any:
    displayed = frame.copy()
    cv2.putText(displayed, "E: enroll test identity | V: recognize | Q: quit", (12, 28),
                cv2.FONT_HERSHEY_SIMPLEX, 0.62, (40, 240, 240), 2, cv2.LINE_AA)
    cv2.putText(displayed, "IDENTITY RECOGNITION ONLY — NO LIVENESS CHECK", (12, 57),
                cv2.FONT_HERSHEY_SIMPLEX, 0.58, (40, 40, 255), 2, cv2.LINE_AA)
    if message:
        cv2.putText(displayed, message[:90], (12, displayed.shape[0] - 18),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.62, (40, 240, 40), 2, cv2.LINE_AA)
    return displayed


def _capture_after_countdown(cv2: Any, capture: Any, frame: Any) -> bytes | None:
    deadline = time.monotonic() + 2.0
    latest_frame = frame.copy()
    while time.monotonic() < deadline:
        ok, candidate = capture.read()
        if ok and candidate is not None and getattr(candidate, "size", 0):
            latest_frame = candidate
        remaining = max(1, int(deadline - time.monotonic()) + 1)
        cv2.imshow(WINDOW_NAME, _show_instructions(cv2, latest_frame, f"Hold still — capture in {remaining}"))
        if cv2.waitKey(1) & 0xFF in (ord("q"), ord("Q")):
            raise KeyboardInterrupt
    ok, final_frame = capture.read()
    if ok and final_frame is not None and getattr(final_frame, "size", 0):
        latest_frame = final_frame
    encoded, image = cv2.imencode(".jpg", latest_frame)
    if not encoded:
        return None
    return image.tobytes()


def _status_for_error(error: Exception) -> str:
    if isinstance(error, InvalidImageError):
        return "Invalid frame — try again"
    if isinstance(error, FaceIdentityNoFace):
        return "No face detected — center one face and retry"
    if isinstance(error, FaceIdentityMultipleFaces):
        return "Multiple faces detected — use one test face only"
    if isinstance(error, FaceEnrollmentExists):
        return "That test ID is already enrolled"
    if isinstance(error, FaceIdentityStorageError):
        return "Demo storage failed safely"
    if isinstance(error, FaceIdentityConfigurationError):
        return "DeepFace model configuration unavailable"
    if isinstance(error, FaceIdentityProviderError):
        return "DeepFace recognition failed — retry"
    return "Recognition failed safely — retry"


def _enroll(cv2: Any, capture: Any, frame: Any, service: FaceIdentityService) -> str:
    user_id = input("Synthetic test identity ID (must start TEST, e.g. TEST001): ").strip().upper()
    if not TEST_ID_PATTERN.fullmatch(user_id):
        return "Rejected: use a test ID such as TEST001"
    image = _capture_after_countdown(cv2, capture, frame)
    if image is None:
        return "Enrollment capture cancelled or frame invalid"
    try:
        metadata = service.enroll(user_id, image)
        print(f"ENROLLMENT SUCCESSFUL — {metadata.user_id} ({metadata.status})")
        return f"ENROLLED {metadata.user_id} — identity only"
    except Exception as error:
        status_text = _status_for_error(error)
        print(f"ENROLLMENT NOT COMPLETED — {status_text}")
        return status_text


def _recognize(cv2: Any, capture: Any, frame: Any, service: FaceIdentityService) -> str:
    image = _capture_after_countdown(cv2, capture, frame)
    if image is None:
        return "Recognition capture cancelled or frame invalid"
    try:
        result = service.identify(image)
        if result.recognition_status == "MATCH" and result.matched:
            print(f"MATCH — {result.user_id} (distance {result.distance:.4f})")
            return f"MATCH — {result.user_id} — NOT LIVENESS"
        print(f"{result.recognition_status} — no identity returned")
        return f"{result.recognition_status} — NO MATCH — NOT LIVENESS"
    except Exception as error:
        status_text = _status_for_error(error)
        print(f"RECOGNITION FAILED — {status_text}")
        return status_text


def main() -> int:
    args = _arguments()
    if _production_environment():
        print("Refusing to run a test protector in a production environment.", file=sys.stderr)
        return 2
    if not args.allow_test_protector:
        print("Pass --allow-test-protector to acknowledge demo-only reversible storage.", file=sys.stderr)
        return 2
    if not args.synthetic_test_data_only:
        print("Pass --synthetic-test-data-only and present synthetic test faces only.", file=sys.stderr)
        return 2

    print("LOCAL TEST MODE ONLY: use synthetic test faces, never a real student's face.")
    print("This camera demo performs identity recognition only; it does not test liveness or spoof resistance.")
    try:
        import cv2
    except ImportError as error:
        print("OpenCV is unavailable. Install the optional DeepFace camera dependencies.", file=sys.stderr)
        return 2

    demo_directory = tempfile.TemporaryDirectory(prefix="verigate-live-camera-demo-")
    capture = None
    try:
        model_name = os.getenv("DEEPFACE_MODEL_NAME", "ArcFace")
        detector_backend = os.getenv("DEEPFACE_DETECTOR_BACKEND", "opencv")
        threshold_value = os.getenv("FACE_COSINE_DISTANCE_THRESHOLD")
        threshold = float(threshold_value) if threshold_value else None
        provider = DeepFaceEmbeddingProvider(model_name=model_name, detector_backend=detector_backend)
        print("Initializing DeepFace model; first use may download model/detector weights.")
        provider.initialize()
        store = SQLiteFaceEnrollmentStore(
            Path(demo_directory.name) / "camera-demo.sqlite3", DemoOnlyProtector()
        )
        service = FaceIdentityService(provider, store, distance_threshold=threshold)

        capture = cv2.VideoCapture(0)
        if not capture.isOpened():
            print("Camera unavailable: could not open cv2.VideoCapture(0).", file=sys.stderr)
            return 1
        try:
            cv2.namedWindow(WINDOW_NAME, cv2.WINDOW_NORMAL)
        except cv2.error as error:
            print(
                "OpenCV GUI support is unavailable. Install opencv-contrib-python (not the headless wheel).",
                file=sys.stderr,
            )
            print(str(error), file=sys.stderr)
            return 1

        status_message = "Ready — test identities only"
        consecutive_bad_frames = 0
        while True:
            ok, frame = capture.read()
            if not ok or frame is None or not getattr(frame, "size", 0):
                consecutive_bad_frames += 1
                status_message = "Camera frame unavailable"
                if consecutive_bad_frames >= 30:
                    print("Camera stopped returning valid frames; exiting safely.", file=sys.stderr)
                    break
                key = cv2.waitKey(30) & 0xFF
                if key in (ord("q"), ord("Q")):
                    break
                continue
            consecutive_bad_frames = 0
            cv2.imshow(WINDOW_NAME, _show_instructions(cv2, frame, status_message))
            key = cv2.waitKey(1) & 0xFF
            if key in (ord("q"), ord("Q")):
                break
            if key in (ord("e"), ord("E")):
                status_message = _enroll(cv2, capture, frame, service)
            elif key in (ord("v"), ord("V")):
                status_message = _recognize(cv2, capture, frame, service)
        return 0
    except KeyboardInterrupt:
        print("Camera demo stopped by user.")
        return 0
    except Exception as error:
        print(f"Camera demo could not start or continue: {error}", file=sys.stderr)
        return 1
    finally:
        if capture is not None:
            capture.release()
        try:
            cv2.destroyAllWindows()
        except Exception:
            pass
        demo_directory.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
