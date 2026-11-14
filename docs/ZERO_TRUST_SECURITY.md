# VERIGATE Zero Trust Security Boundaries

- **Caller identity:** The host application must authenticate each caller and
  bind or authorize the submitted `user_id` before routing the request. The
  access router does not authenticate users by itself.
- **Evidence:** Client-supplied evidence is only a claim. Trusted issuer
  adapters validate evidence and bind it to the user and authentication
  attempt. Biometric success cannot override spoof detection or a failed
  mandatory check.
- **Campus records:** The API accepts no campus records, source authority,
  authority ranks, or precomputed decisions. Server-side providers supply
  records; per-domain configuration establishes which sources may issue them.
- **Authorization:** Identity evidence establishes confidence in who is
  present. Campus records and policy determine whether that person may access
  the requested resource. No majority voting is used.
- **Fail closed:** Suspensions, confirmed revocations, explicit denials,
  missing permissions, unresolved conflicts, and required stale or unavailable
  revocation data cannot produce `ALLOW`. Provider or internal evaluation
  failures return a safe denial or an HTTP error; they never default to access.
- **Audit:** `build_audit_event` records request and decision identifiers plus
  safe outcome summaries. It excludes raw images, fingerprint templates,
  credentials, tokens, evidence provenance, and record-level provenance.
  `explain_reason_codes` produces deterministic text and does not change the
  decision.
- **Persistence:** AWS/DynamoDB persistence and durable audit storage are not
  integrated. Audit events exist only as in-memory structured models until a
  separately reviewed persistence integration is implemented.

The router remains standalone and is not mounted in `backend/app/main.py` by
this module. Production use still requires reviewed provider implementations,
server-owned policy configuration, host authentication, and a secure audit
retention design.
