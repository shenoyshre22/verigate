# Face Authentication

This module contains face identity recognition as one stage of Face
Authentication. Face liveness is an independent stage and is not implemented
here.

## Recognition endpoint

`POST /api/v1/face-auth/recognize` accepts multipart form fields `user_id`
and `image`. It compares the submitted image to the enrolled reference returned
by a `ReferenceImageProvider` using Amazon Rekognition `DetectFaces` and
`CompareFaces`. The response reports the measured similarity, configured
threshold, and preprocessing, AWS, and total recognition latency separately.

Recognition returns `MATCH` only when Rekognition returns a similarity at or
above the configured threshold. The threshold is a decision parameter, not a
guarantee of security or accuracy. Set `FACE_SIMILARITY_THRESHOLD` based on
evaluation for the intended population and use case.

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
