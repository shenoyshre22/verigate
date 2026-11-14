# Face Authentication

This module contains face identity recognition as one stage of Face
Authentication. Face liveness is an independent stage and is not implemented
here.

## Recognition endpoint

`POST /api/v1/face-auth/recognize` accepts multipart form fields `user_id`
and `image`. It compares the submitted image to the enrolled reference returned
by a `ReferenceImageProvider` using Amazon Rekognition `DetectFaces` and
`CompareFaces` by default. Set `FACE_RECOGNITION_ENGINE=deepface` to use the
optional adapter to the vendored upstream DeepFace source instead. Exactly one
provider is called per request; the backends are not combined or majority-voted.
The response reports the measured similarity, configured threshold, and
preprocessing, AWS, provider, and total recognition latency separately.

Recognition returns `MATCH` only when the selected provider reports a match and
the measured confidence reaches the configured threshold. The threshold is a
decision parameter, not a guarantee of security or accuracy. Set
`FACE_SIMILARITY_THRESHOLD` based on evaluation for the intended population and
use case. DeepFace's built-in verification decision is also required to be true.

The current local provider loads `<user_id>.jpg`, `.jpeg`, or `.png` from
`FACE_REFERENCE_DIR`. This is for controlled local development only. Production
must replace it with an appropriately enrolled and access-controlled reference
provider. The provider interface is in `reference_provider.py`.

Submitted and reference images are validated as JPEG or PNG, limited to less
than 5 MB, and required to contain exactly one detectable face before comparison. Raw
image bytes are not logged or persisted by this module.

The combined `/api/v1/face-auth/verify` endpoint is pending the documented
liveness service contract. Recognition alone never produces an overall
`AUTHENTICATED` result.

For the optional DeepFace backend, install dependencies in an isolated
environment with `python -m pip install -r backend/requirements-deepface.txt`.
Upstream model weights are downloaded separately on first use. The optional
backend performs 1:1 comparison only; persistent enrollment, 1:N campus identity
search, authenticated user/attempt binding, trusted evidence generation, and
AWS-backed DeepFace mapping are not implemented by this adapter.
