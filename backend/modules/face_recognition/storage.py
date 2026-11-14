"""Local persistent embedding metadata with Windows user-scoped DPAPI protection."""

from __future__ import annotations

import ctypes
import json
import os
import sqlite3
from contextlib import closing
from ctypes import POINTER, Structure, byref, c_byte, c_uint32, c_void_p, c_wchar_p, cast, string_at
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from .embedding_provider import FaceEmbedding
from .errors import (
    FaceEnrollmentExists,
    FaceEnrollmentNotFound,
    FaceIdentityConfigurationError,
    FaceIdentityStorageError,
)


class DataProtector(Protocol):
    def protect(self, data: bytes, context: bytes) -> bytes: ...

    def unprotect(self, data: bytes, context: bytes) -> bytes: ...


class WindowsDpapiProtector:
    """Use Windows DPAPI CurrentUser; the encrypted value cannot be moved to another user."""

    class _DataBlob(Structure):
        _fields_ = [("cbData", c_uint32), ("pbData", POINTER(c_byte))]

    def __init__(self) -> None:
        if os.name != "nt":
            raise FaceIdentityConfigurationError(
                "Local embedding storage requires Windows DPAPI; use the approved server vector store in deployment."
            )
        self._crypt32 = ctypes.WinDLL("Crypt32", use_last_error=True)
        self._kernel32 = ctypes.WinDLL("Kernel32", use_last_error=True)

    @classmethod
    def _blob(cls, data: bytes):
        buffer = (c_byte * len(data)).from_buffer_copy(data)
        return cls._DataBlob(len(data), cast(buffer, POINTER(c_byte))), buffer

    def _crypt(self, data: bytes, context: bytes, *, decrypt: bool) -> bytes:
        input_blob, input_buffer = self._blob(data)
        entropy_blob, entropy_buffer = self._blob(context)
        output_blob = self._DataBlob()
        forbidden_ui = 0x1
        if decrypt:
            function = self._crypt32.CryptUnprotectData
            function.argtypes = [
                POINTER(self._DataBlob), POINTER(c_void_p), POINTER(self._DataBlob), c_void_p,
                c_void_p, c_uint32, POINTER(self._DataBlob),
            ]
            function.restype = ctypes.c_int
            ok = function(byref(input_blob), None, byref(entropy_blob), None, None,
                          forbidden_ui, byref(output_blob))
        else:
            function = self._crypt32.CryptProtectData
            function.argtypes = [
                POINTER(self._DataBlob), c_wchar_p, POINTER(self._DataBlob), c_void_p,
                c_void_p, c_uint32, POINTER(self._DataBlob),
            ]
            function.restype = ctypes.c_int
            ok = function(byref(input_blob), "VERIGATE face embedding", byref(entropy_blob),
                          None, None, forbidden_ui, byref(output_blob))
        # Keep input buffers alive until the native call has returned.
        _ = input_buffer, entropy_buffer
        if not ok:
            raise OSError(ctypes.get_last_error(), "Windows DPAPI operation failed")
        try:
            return string_at(output_blob.pbData, output_blob.cbData)
        finally:
            self._kernel32.LocalFree.argtypes = [c_void_p]
            self._kernel32.LocalFree.restype = c_void_p
            self._kernel32.LocalFree(cast(output_blob.pbData, c_void_p))

    def protect(self, data: bytes, context: bytes) -> bytes:
        return self._crypt(data, context, decrypt=False)

    def unprotect(self, data: bytes, context: bytes) -> bytes:
        return self._crypt(data, context, decrypt=True)


@dataclass(frozen=True)
class EnrollmentMetadata:
    user_id: str
    model_name: str
    model_version: str
    detector_backend: str
    embedding_dimension: int
    enrolled_at: datetime
    status: str


class SQLiteFaceEnrollmentStore:
    """Prototype persistence: only encrypted vectors are stored, never uploaded images."""

    def __init__(self, database_path: str | Path, protector: DataProtector) -> None:
        if protector is None:
            raise FaceIdentityConfigurationError("An embedding data protector is required.")
        self._path = Path(database_path).expanduser().resolve()
        self._protector = protector
        self._path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with closing(self._connect()) as connection:
                connection.execute(
                    """CREATE TABLE IF NOT EXISTS face_enrollments (
                        user_id TEXT PRIMARY KEY,
                        embedding_ciphertext BLOB,
                        embedding_dimension INTEGER NOT NULL,
                        model_name TEXT NOT NULL,
                        model_version TEXT NOT NULL,
                        detector_backend TEXT NOT NULL,
                        enrolled_at TEXT NOT NULL,
                        status TEXT NOT NULL CHECK (status IN ('ACTIVE', 'DELETED'))
                    )"""
                )
        except sqlite3.Error as error:
            raise FaceIdentityStorageError("Face enrollment storage could not be initialized.") from error

    def _connect(self):
        connection = sqlite3.connect(self._path, timeout=10, isolation_level=None)
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection

    @staticmethod
    def _context(user_id: str, model_version: str) -> bytes:
        return f"VERIGATE/DeepFace/v1/{user_id}/{model_version}".encode("utf-8")

    @staticmethod
    def _metadata(row) -> EnrollmentMetadata:
        return EnrollmentMetadata(
            user_id=row[0],
            model_name=row[1],
            model_version=row[2],
            detector_backend=row[3],
            embedding_dimension=row[4],
            enrolled_at=datetime.fromisoformat(row[5]),
            status=row[6],
        )

    def enroll(self, user_id: str, embedding: FaceEmbedding, *, replace: bool = False) -> EnrollmentMetadata:
        vector_data = json.dumps(embedding.vector, allow_nan=False, separators=(",", ":")).encode("utf-8")
        context = self._context(user_id, embedding.model_version)
        try:
            ciphertext = self._protector.protect(vector_data, context)
            enrolled_at = datetime.now(timezone.utc)
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT status FROM face_enrollments WHERE user_id = ?", (user_id,)
                ).fetchone()
                if row is not None and row[0] == "ACTIVE" and not replace:
                    connection.rollback()
                    raise FaceEnrollmentExists("An active face enrollment already exists for this user.")
                connection.execute(
                    """INSERT INTO face_enrollments
                       (user_id, embedding_ciphertext, embedding_dimension, model_name,
                        model_version, detector_backend, enrolled_at, status)
                       VALUES (?, ?, ?, ?, ?, ?, ?, 'ACTIVE')
                       ON CONFLICT(user_id) DO UPDATE SET
                         embedding_ciphertext=excluded.embedding_ciphertext,
                         embedding_dimension=excluded.embedding_dimension,
                         model_name=excluded.model_name,
                         model_version=excluded.model_version,
                         detector_backend=excluded.detector_backend,
                         enrolled_at=excluded.enrolled_at,
                         status='ACTIVE'""",
                    (user_id, ciphertext, len(embedding.vector), embedding.model_name,
                     embedding.model_version, embedding.detector_backend, enrolled_at.isoformat()),
                )
                connection.commit()
            return EnrollmentMetadata(
                user_id, embedding.model_name, embedding.model_version,
                embedding.detector_backend, len(embedding.vector), enrolled_at, "ACTIVE"
            )
        except FaceEnrollmentExists:
            raise
        except (sqlite3.Error, OSError, ValueError) as error:
            raise FaceIdentityStorageError("Face enrollment could not be persisted safely.") from error

    def get(self, user_id: str) -> EnrollmentMetadata:
        try:
            with closing(self._connect()) as connection:
                row = connection.execute(
                    """SELECT user_id, model_name, model_version, detector_backend,
                              embedding_dimension, enrolled_at, status
                       FROM face_enrollments WHERE user_id = ?""",
                    (user_id,),
                ).fetchone()
        except sqlite3.Error as error:
            raise FaceIdentityStorageError("Face enrollment status could not be read.") from error
        if row is None:
            raise FaceEnrollmentNotFound("No face enrollment exists for this user.")
        return self._metadata(row)

    def delete(self, user_id: str) -> EnrollmentMetadata:
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                result = connection.execute(
                    "UPDATE face_enrollments SET status='DELETED', embedding_ciphertext=NULL WHERE user_id=? AND status='ACTIVE'",
                    (user_id,),
                )
                if result.rowcount == 0:
                    connection.rollback()
                    raise FaceEnrollmentNotFound("No active face enrollment exists for this user.")
                row = connection.execute(
                    """SELECT user_id, model_name, model_version, detector_backend,
                              embedding_dimension, enrolled_at, status
                       FROM face_enrollments WHERE user_id = ?""",
                    (user_id,),
                ).fetchone()
                connection.commit()
        except FaceEnrollmentNotFound:
            raise
        except sqlite3.Error as error:
            raise FaceIdentityStorageError("Face enrollment could not be deleted.") from error
        return self._metadata(row)

    def active_embeddings(self, model_version: str) -> list[tuple[EnrollmentMetadata, tuple[float, ...]]]:
        try:
            with closing(self._connect()) as connection:
                rows = connection.execute(
                    """SELECT user_id, embedding_ciphertext, model_name, model_version,
                              detector_backend, embedding_dimension, enrolled_at, status
                       FROM face_enrollments WHERE status='ACTIVE' AND model_version=?""",
                    (model_version,),
                ).fetchall()
            result = []
            for row in rows:
                metadata = EnrollmentMetadata(
                    user_id=row[0], model_name=row[2], model_version=row[3],
                    detector_backend=row[4], embedding_dimension=row[5],
                    enrolled_at=datetime.fromisoformat(row[6]), status=row[7],
                )
                context = self._context(metadata.user_id, metadata.model_version)
                plaintext = self._protector.unprotect(row[1], context)
                vector = json.loads(plaintext.decode("utf-8"))
                if (
                    not isinstance(vector, list)
                    or len(vector) != metadata.embedding_dimension
                    or any(isinstance(value, bool) or not isinstance(value, (int, float)) for value in vector)
                ):
                    raise ValueError("Stored face representation is invalid.")
                result.append((metadata, tuple(float(value) for value in vector)))
            return result
        except (sqlite3.Error, OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as error:
            raise FaceIdentityStorageError("Stored face representations could not be read safely.") from error


def default_local_store() -> SQLiteFaceEnrollmentStore:
    database = os.getenv("FACE_ENROLLMENT_DB")
    if not database:
        local_app_data = os.getenv("LOCALAPPDATA")
        if not local_app_data:
            raise FaceIdentityConfigurationError("FACE_ENROLLMENT_DB or LOCALAPPDATA must be configured.")
        database = str(Path(local_app_data) / "VERIGATE" / "face-enrollments.sqlite3")
    return SQLiteFaceEnrollmentStore(database, WindowsDpapiProtector())
