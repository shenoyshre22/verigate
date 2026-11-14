# DeepFace and VERIGATE integration

## Current boundary

The upstream DeepFace project is imported unchanged under `backend/external/deepface/`. VERIGATE's existing face module remains under `backend/modules/face_authentication/`; it validates images and uses Amazon Rekognition `DetectFaces` and `CompareFaces` for 1:1 comparison. Liveness remains its own stage. The current recognition route compares against a caller-selected `user_id` reference and does not perform open-set 1:N campus identity retrieval or enrollment.

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

The optional 1:1 adapter does not provide campus-wide 1:N retrieval, an enrollment endpoint/store, authenticated user or attempt binding, trusted evidence generation, or Zero Trust integration. No existing Rekognition default or liveness behavior was replaced.
