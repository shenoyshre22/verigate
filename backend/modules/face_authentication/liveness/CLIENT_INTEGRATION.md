# Face Liveness Client Integration

This is the agreed client handoff for the liveness router. The client uses the
session ID returned by the backend, completes capture with the supported AWS
client flow, then asks the backend for the result. The user identity must come
from the host application's verified authentication principal.

The route shape and result fields below match the current standalone router.
Authentication and durable ownership storage still need host-app wiring before
these endpoints can serve successful requests.

The latest shared branch's Lambda handler auto-includes this router when
`main.py` does not. The router still returns 503 until the host application
overrides both the verified-user and durable-ownership dependencies. Local
`backend/app/main.py` does not currently include the router.

## Flow

1. The signed-in client calls `POST /api/v1/face-auth/liveness/session` with
   `{"authentication_attempt_id":"<active-attempt-id>"}`. The backend obtains
   `user_id` from its verified authentication principal; clients must not choose
   another user's ID.
2. The backend verifies that the authenticated user owns the active attempt,
   creates a Rekognition session, and durably binds its `session_id` to that
   user and attempt before returning it.
3. The browser runs a supported AWS Face Liveness client flow with the returned
   session ID and the same AWS region configured for the backend. With Amplify
   UI for React, this is `FaceLivenessDetector`; it performs the streaming
   capture and calls `onAnalysisComplete` when analysis is complete. The
   browser does not call `GetFaceLivenessSessionResults` directly.
4. On `onAnalysisComplete`, the browser calls
   `GET /api/v1/face-auth/liveness/session/{session_id}/result` as the same
   authenticated user. If the result is still `PENDING`, it may poll with a
   modest delay/backoff. Only the backend classifies the AWS confidence and
   returns the result.
5. A capture error requires a new session before retrying. Do not reuse the
   previous session ID.

## API contract

Session creation:

```http
POST /api/v1/face-auth/liveness/session
Content-Type: application/json
```

```json
{"authentication_attempt_id":"attempt-123"}
```

The current standalone route returns HTTP 201 with `module`, `user_id`,
`authentication_attempt_id`, `session_id`, and `status: "PENDING"`.

Result retrieval returns `module`, `user_id`, `session_id`, `status`,
`confidence` when AWS supplied a valid numeric confidence, `latency_ms`, and
safe `error` details where applicable. Current provider failures use safe HTTP
errors (for example, 502/503/504); the route does not currently emit a JSON
`status: "ERROR"` result.

`latency_ms` currently measures the backend's result-fetch request duration;
it does not represent the user's capture time or full liveness processing
duration. Keep this separate from recognition latency.

## React integration example

This example shows the frontend handoff. `authenticatedFetch` must use the
host application's existing authentication. The frontend does not send a
`user_id`; the backend derives it from the verified principal.

```tsx
import { useState } from 'react';
import { FaceLivenessDetector } from '@aws-amplify/ui-react-liveness';

type Session = { session_id: string };
type Result = {
  status: 'PENDING' | 'LIVE' | 'SPOOF' | 'EXPIRED' | 'INDETERMINATE' | 'ERROR';
  confidence: number | null;
  error: string | null;
};

const API_BASE = import.meta.env.VITE_API_BASE_URL;
const REGION = import.meta.env.VITE_AWS_REGION;

// Implement with the app's current cookie or bearer-token auth.
declare function authenticatedFetch(path: string, init?: RequestInit): Promise<Response>;
const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

async function createSession(attemptId: string): Promise<Session> {
  const response = await authenticatedFetch(`${API_BASE}/api/v1/face-auth/liveness/session`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ authentication_attempt_id: attemptId }),
  });
  if (!response.ok) throw new Error('Could not start liveness verification.');
  return response.json();
}

async function getResult(sessionId: string): Promise<Result> {
  let delayMs = 500;
  for (let count = 0; count < 8; count += 1) {
    const response = await authenticatedFetch(
      `${API_BASE}/api/v1/face-auth/liveness/session/${encodeURIComponent(sessionId)}/result`,
    );
    if (!response.ok) throw new Error('Could not retrieve the liveness result.');
    const result: Result = await response.json();
    if (result.status !== 'PENDING') return result;
    await wait(delayMs);
    delayMs = Math.min(delayMs * 2, 4000);
  }
  throw new Error('Verification is taking longer than expected.');
}

export function LivenessCapture({ attemptId }: { attemptId: string }) {
  const [session, setSession] = useState<Session | null>(null);
  const [message, setMessage] = useState('Preparing camera verification…');

  async function startNewSession() {
    setMessage('Preparing camera verification…');
    setSession(await createSession(attemptId));
  }

  async function handleAnalysisComplete() {
    try {
      const result = await getResult(session!.session_id);
      setMessage({
        LIVE: 'Liveness passed. Continuing to identity recognition…',
        SPOOF: 'Liveness was not established. Start a new attempt to retry.',
        EXPIRED: 'This verification expired. Start a new attempt to retry.',
        INDETERMINATE: 'Liveness could not be determined. Start a new attempt to retry.',
        ERROR: 'Verification failed. Start a new attempt to retry.',
        PENDING: 'Verification is still processing.',
      }[result.status]);
      setSession(null);
    } catch {
      setMessage('Verification could not be completed. Start a new attempt to retry.');
      setSession(null);
    }
  }

  if (!session) {
    return (
      <>
        <p role="status">{message}</p>
        <button onClick={() => void startNewSession()}>Start a new liveness session</button>
      </>
    );
  }

  return (
    <>
      <FaceLivenessDetector
        key={session.session_id}
        sessionId={session.session_id}
        region={REGION}
        onAnalysisComplete={handleAnalysisComplete}
        onError={() => {
          setMessage('Camera check failed. Start a new attempt to retry.');
          setSession(null);
        }}
      />
      <p role="status">{message}</p>
    </>
  );
}
```

Create a new backend session for every retry; a capture session is single-use.
The `LIVE` message represents only the liveness stage, not an identity match or
an access decision.

## Client display behavior

| Result | Client behavior |
| --- | --- |
| `PENDING` | Show that verification is still processing; poll with backoff. |
| `LIVE` | Show that the liveness stage passed. Continue to identity recognition; this is not an identity match or access decision. |
| `SPOOF` | Show that liveness was not established; offer a new attempt only through a newly created session. |
| `EXPIRED` | Tell the user the attempt expired and start a new session if retry is allowed. |
| `INDETERMINATE` | Show that liveness could not be determined; do not treat it as `LIVE`. Retry only with a new session if appropriate. |
| HTTP/provider error | Show a safe retry or service-unavailable message; never treat a failed request as `LIVE`. |

## Security and configuration

- The backend needs the Rekognition region. The frontend must use the same
  region for the capture stream.
- Never put long-lived AWS access keys or secret access keys in frontend code.
  Amplify UI's documented setup uses a Cognito Identity Pool (including
  unauthenticated identities) or a custom credential provider to supply
  temporary AWS credentials for streaming. Any identity-pool role must be
  narrowly scoped to the required Face Liveness streaming operation; coordinate
  this client credential model with the AWS/infrastructure owner. The current
  repo does not include an identity-pool configuration.
- Keep session IDs tied to the authenticated owner in durable backend storage.
  Never trust a client-supplied user ID or an unowned session ID.
- Do not upload or log raw camera frames. This module does not request S3 output
  storage or persist Rekognition reference/audit image bytes.
- Rekognition Face Liveness session IDs expire three minutes after creation.
  The backend's default local TTL is 170 seconds to avoid querying at the AWS
  expiry boundary. Create a new session for every retry.
- Tune and evaluate the confidence threshold for the deployment. A confidence
  value or a passing liveness result does not establish identity or authorize
  access by itself.

## References

- [Amazon Rekognition Face Liveness programming guide](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness-programming-api.html)
- [Amplify UI for React Face Liveness](https://ui.docs.amplify.aws/react/connected-components/liveness?platform=react)
- [CreateFaceLivenessSession API](https://docs.aws.amazon.com/rekognition/latest/APIReference/API_CreateFaceLivenessSession.html)
