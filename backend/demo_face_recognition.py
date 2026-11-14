"""Local-only DeepFace demo. Never use this test protector with real biometric data."""

from __future__ import annotations

import argparse
import gc
import os
import sys
import tempfile
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from backend.modules.face_recognition.embedding_provider import DeepFaceEmbeddingProvider  # noqa: E402
from backend.modules.face_recognition.errors import FaceEnrollmentExists  # noqa: E402
from backend.modules.face_recognition.service import FaceIdentityService  # noqa: E402
from backend.modules.face_recognition.storage import SQLiteFaceEnrollmentStore  # noqa: E402
from backend.tests.face_recognition.test_face_identity import TestProtector as DemoOnlyProtector  # noqa: E402


def _production_environment() -> bool:
    production_markers = ("AWS_LAMBDA_FUNCTION_NAME", "AWS_EXECUTION_ENV", "ECS_CONTAINER_METADATA_URI_V4", "K_SERVICE")
    return any(os.getenv(name) for name in production_markers) or any(
        os.getenv(name, "").strip().lower() in {"production", "prod"}
        for name in ("APP_ENV", "VERIGATE_ENV", "ENVIRONMENT")
    )


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Demonstrate the existing VERIGATE DeepFace service using synthetic/test data only."
    )
    parser.add_argument(
        "--use-upstream-test-images",
        action="store_true",
        help="Use DeepFace's bundled unit-test fixtures (their image-specific terms are not included here).",
    )
    parser.add_argument("--test001", type=Path, help="Synthetic/test face image for TEST001 (JPEG or PNG).")
    parser.add_argument("--test002", type=Path, help="Different synthetic/test face image for TEST002.")
    parser.add_argument("--unknown", type=Path, help="A third synthetic/test identity, absent from enrollment.")
    parser.add_argument(
        "--allow-test-protector",
        action="store_true",
        help="Required acknowledgement: this demo uses the reversible XOR test protector, never production encryption.",
    )
    args = parser.parse_args()

    custom_images = (args.test001, args.test002, args.unknown)
    if args.use_upstream_test_images and any(custom_images):
        parser.error("Choose upstream fixtures or provide all three custom images, not both.")
    if not args.use_upstream_test_images and not all(custom_images):
        parser.error(
            "Provide --test001, --test002 and --unknown, or explicitly opt into bundled fixtures with "
            "--use-upstream-test-images."
        )
    if not args.allow_test_protector:
        parser.error("Pass --allow-test-protector to acknowledge this isolated test-only storage mode.")
    return args


def _image_paths(args: argparse.Namespace) -> tuple[Path, Path, Path, Path, Path]:
    if args.use_upstream_test_images:
        dataset = REPOSITORY_ROOT / "backend" / "external" / "deepface" / "tests" / "unit" / "dataset"
        paths = (
            dataset / "img1.jpg", dataset / "img2.jpg",
            dataset / "img20.jpg", dataset / "img21.jpg", dataset / "img16.jpg",
        )
        absent = [str(path) for path in paths if not path.is_file()]
        if absent:
            raise FileNotFoundError(
                "DeepFace sample image(s) are missing: " + ", ".join(absent)
                + ". Supply synthetic images with --test001, --test002 and --unknown."
            )
        print("Using bundled upstream test fixtures; no student images are used or downloaded.")
        print("Image-specific reuse terms are not included in the vendored source; confirm local-use permission.")
        return paths

    paths = (args.test001, args.test002, args.unknown)
    for path in paths:
        if not path.is_file():
            raise FileNotFoundError(f"Test image not found: {path}")
    # Custom inputs use the same synthetic image for enrollment and probe. The upstream fixture
    # option includes separate same-identity probe images for a stronger local demonstration.
    return paths[0], paths[0], paths[1], paths[1], paths[2]


def _assert_match(service: FaceIdentityService, image: bytes, expected_user: str) -> None:
    result = service.identify(image)
    if not result.matched or result.user_id != expected_user:
        raise RuntimeError(
            f"Expected {expected_user}, got {result.recognition_status} ({result.user_id!r}); "
            "check image selection and use a calibrated threshold for real evaluation."
        )
    print("RECOGNITION SUCCESSFUL")
    print(f"Matched User: {result.user_id}")
    print(f"Recognition Status: {result.recognition_status}")
    print(f"Cosine Distance: {result.distance:.4f} (threshold {result.threshold:.4f})")


def main() -> int:
    args = _arguments()
    if _production_environment():
        print("Refusing to run the test-only protector in a production environment.", file=sys.stderr)
        return 2

    enroll001_path, probe001_path, enroll002_path, probe002_path, unknown_path = _image_paths(args)
    image001 = enroll001_path.read_bytes()
    probe001 = probe001_path.read_bytes()
    image002 = enroll002_path.read_bytes()
    probe002 = probe002_path.read_bytes()
    unknown_image = unknown_path.read_bytes()

    demo_root = Path(tempfile.mkdtemp(prefix="verigate-face-demo-"))
    database_path = demo_root / "face-enrollments.sqlite3"
    print("WARNING: isolated local demonstration using synthetic/test images and a reversible test-only protector.")
    print("Do not use this mode or protector for student, personal, or production biometric data.")
    print(f"Demo-only SQLite database: {database_path}")

    provider = DeepFaceEmbeddingProvider(
        model_name=os.getenv("DEEPFACE_MODEL_NAME", "ArcFace"),
        detector_backend=os.getenv("DEEPFACE_DETECTOR_BACKEND", "opencv"),
    )
    provider.initialize()
    protector = DemoOnlyProtector()
    store = SQLiteFaceEnrollmentStore(database_path, protector)
    threshold_setting = os.getenv("FACE_COSINE_DISTANCE_THRESHOLD")
    threshold = float(threshold_setting) if threshold_setting else None
    service = FaceIdentityService(provider, store, distance_threshold=threshold)

    for user_id, image in (("TEST001", image001), ("TEST002", image002)):
        metadata = service.enroll(user_id, image)
        print("ENROLLMENT SUCCESSFUL")
        print(f"User ID: {metadata.user_id}")
        print(f"Enrollment Status: {service.enrollment_status(user_id).status}")

    try:
        service.enroll("TEST001", image001)
    except FaceEnrollmentExists:
        print("DUPLICATE ENROLLMENT")
        print("Expected rejection confirmed.")
    else:
        raise RuntimeError("Duplicate enrollment unexpectedly succeeded.")

    print("\nInitial recognition")
    _assert_match(service, probe001, "TEST001")
    _assert_match(service, probe002, "TEST002")
    unknown_result = service.identify(unknown_image)
    if unknown_result.recognition_status != "UNKNOWN" or unknown_result.user_id is not None:
        raise RuntimeError(
            f"Unknown test identity was not rejected as UNKNOWN: {unknown_result.recognition_status} "
            f"({unknown_result.user_id!r})."
        )
    print("UNKNOWN FACE")
    print(f"Recognition Status: {unknown_result.recognition_status}")

    # SQLiteFaceEnrollmentStore opens and closes each connection within each method.
    # Drop the first service/store/provider, then construct fresh instances over the same file.
    del service, store, provider
    gc.collect()
    provider = DeepFaceEmbeddingProvider(
        model_name=os.getenv("DEEPFACE_MODEL_NAME", "ArcFace"),
        detector_backend=os.getenv("DEEPFACE_DETECTOR_BACKEND", "opencv"),
    )
    provider.initialize()
    reopened_store = SQLiteFaceEnrollmentStore(database_path, DemoOnlyProtector())
    service = FaceIdentityService(provider, reopened_store, distance_threshold=threshold)
    _assert_match(service, probe001, "TEST001")
    _assert_match(service, probe002, "TEST002")
    print("PERSISTENCE")
    print("Both identities successfully recognized after service restart.")

    deleted = service.delete_enrollment("TEST001")
    if deleted.status != "DELETED":
        raise RuntimeError("Expected TEST001 enrollment to be marked DELETED.")
    after_delete = service.identify(probe001)
    if after_delete.recognition_status != "UNKNOWN" or after_delete.user_id is not None:
        raise RuntimeError("Deleted TEST001 identity was still returned by recognition.")
    print("DELETION")
    print("TEST001 is no longer recognized; result is UNKNOWN.")
    print(f"Demo database retained at: {database_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
