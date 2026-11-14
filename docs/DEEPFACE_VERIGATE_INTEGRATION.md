# DeepFace and VERIGATE integration

## Current boundary

The upstream DeepFace project is imported unchanged under `backend/external/deepface/`. VERIGATE's existing face module remains under `backend/modules/face_authentication/`; it validates images and uses Amazon Rekognition `DetectFaces` and `CompareFaces` for 1:1 comparison. Liveness remains its own stage. A separate `backend/modules/face_recognition/` module now implements local enrollment, protected representation persistence and open-set 1:N identification. The app registers its router under `/api/v1/face`; the existing `/api/v1/face-auth` routes and `/health` remain registered.

An optional adapter in `backend/modules/face_authentication/deepface_client.py` now calls the vendored DeepFace `extract_faces` and `verify` APIs for 1:1 comparison. `FACE_RECOGNITION_ENGINE` selects either `rekognition` (default) or `deepface` for a process; both are never called for the same comparison. The adapter requires DeepFace's own `verified` result and also applies VERIGATE's configured confidence threshold. It disables DeepFace anti-spoofing because liveness is a separate stage. Dependencies are isolated in `backend/requirements-deepface.txt` and are not added to shared backend requirements.

The current FastAPI app includes the face-authentication router. The separate decision engine lives at `backend/modules/decision_engine/` on this branch; there is no `backend/modules/zero_trust/` directory here. The decision engine remains the only component that can decide access. DeepFace results must never grant access directly.

## Upstream capabilities confirmed from source

DeepFace exposes face detection/extraction, representation generation, pair verification, gallery search, and database-backed register/identify/search operations. It supports multiple model and detector backends and distance metrics. The source includes adapters for several SQL, graph, and vector databases, plus local, S3, and FTP file stores for gallery images. Its database adapter inventory does not include DynamoDB.

The upstream `verify` operation is a pairwise identity comparison. `find` searches an image gallery and returns matching gallery identities; it is not an authorization decision. Unknown faces must remain unknown when no result passes the configured recognition threshold.

## Recommended deployment boundary

Keep the existing Amazon Rekognition integration as the production recognition provider for the current Lambda deployment. The Lambda package is Python 3.12, while DeepFace brings native computer-vision/model dependencies and downloads model weights separately. DeepFace inference in Lambda should be considered only after measuring the selected model, detector, package size, cold-start time, memory, and model download strategy in a deployment-compatible build.

Use the imported DeepFace source in an isolated evaluation environment to compare candidate model/detector/metric combinations against a consented, representative dataset. Do not run Rekognition and DeepFace as competing sources of an access decision. If the team later chooses DeepFace for production, implement one server-side provider behind the existing recognition service interface and select that provider per deployment; preserve Rekognition liveness as a distinct stage.

## Required VERIGATE-owned work before enrollment or evidence endpoints

1. Establish the authenticated principal and map its verified claim to the canonical campus user ID. Do not accept that mapping from the request body.
2. Establish the authentication-attempt creation and validation store. Bind enrollment/recognition evidence to that server-created attempt.
3. Decide whether enrollment stores a reference image, encrypted representation, or a managed Rekognition collection entry. Document retention, re-enrollment, deletion, model versioning, and biometric consent first.
4. Create a server-side enrollment and recognition adapter that validates exactly one face and emits a safe result with module, user, attempt, outcome, timestamp, and trusted issuer metadata.
5. Pass server-verified evidence to the decision engine. Do not expose a client-controlled match boolean, identity, score, or issuer as trusted evidence.
6. Test unknown identities, duplicate enrollment, revocation, spoof precedence, and authorization denial before enabling access decisions.

The new service uses ArcFace embeddings and cosine distance, accepts one detected face, filters stored records by exact model version and returns `UNKNOWN` when no single enrollment is within the configured threshold. Multiple qualifying identities return `AMBIGUOUS`; the nearest record is never automatically chosen in that case. The threshold defaults to DeepFace's ArcFace cosine threshold and can be overridden with `FACE_COSINE_DISTANCE_THRESHOLD` (range 0–2). This value is a starting point only and must be calibrated against a consented campus dataset; synthetic tests are not accuracy evidence.

On Windows, the local prototype stores only embeddings encrypted with user-scoped DPAPI in SQLite; it does not persist uploaded images. DPAPI requires an available current-user profile; storage errors fail closed. Configure `FACE_ENROLLMENT_DB` to select the database path, otherwise the database is under the current user's `%LOCALAPPDATA%\VERIGATE`. Set `DEEPFACE_HOME` to a writable model cache path if needed. ArcFace weights and OpenCV Haar cascade assets are downloaded on first use. Install using `python -m pip install -r backend/requirements-deepface.txt` from the repository root. On Windows, use a UTF-8 Python console (`PYTHONUTF8=1`) for upstream download logs.

The routes exist, but production authentication is intentionally unavailable until the host wires `get_authenticated_principal` to a verified token or terminal identity provider. Enrollment, status and deletion require `face:enroll` or `admin`. `/verify` additionally requires a trusted attempt ID and in-process evidence sink. A match must equal the authenticated principal before trusted evidence can be emitted. The current branch has no such provider/sink, so these routes fail closed with HTTP 503 by default; this is an integration boundary, not a functioning end-to-end login flow. Face recognition evidence never grants campus access and cannot replace liveness or the deterministic decision engine.

No AWS enrollment store is implemented. No AWS resources were created or changed. The local SQLite/DPAPI store is a development adapter, not a multi-instance production data store.

## Local live-camera identity demo

Run `backend/demo_live_camera.py` from the repository root with `--allow-test-protector --synthetic-test-data-only`. The demo uses the existing provider, service and SQLite repository with a disposable temporary database. It accepts enrollment IDs beginning with `TEST` only, refuses production-marked environments, and requires explicit confirmation that only synthetic test faces will be presented. The test protector is reversible and is never used by the production application. The camera flow performs identity recognition only; it does not test liveness or spoof resistance. Do not use student or other real-person biometric data.

The DeepFace package installs `opencv-contrib-python-headless`, which cannot display a camera window. The optional requirements also include the GUI-enabled `opencv-contrib-python`; on Windows replace the headless wheel after installing the requirements:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r backend\requirements-deepface.txt
.\.venv\Scripts\python.exe -m pip uninstall -y opencv-contrib-python-headless
.\.venv\Scripts\python.exe -m pip install --force-reinstall --no-deps "opencv-contrib-python>=4.9,<5"
$env:PYTHONUTF8 = '1'
.\.venv\Scripts\python.exe backend\demo_live_camera.py --allow-test-protector --synthetic-test-data-only
```

The first model/detector use may download DeepFace weights. In the camera window, press **E** and enter a `TEST...` ID to enroll, **V** to recognize the current face, or **Q** to quit. The host must have a camera and GUI-capable OpenCV. FastAPI's enrollment and recognition routes still require host authentication providers; this local harness does not bypass those checks.
