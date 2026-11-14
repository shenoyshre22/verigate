# Face Recognition Evaluation Procedure

Use a consented, access-controlled dataset with known identity labels. Keep
enrollment references and verification samples separate where the evaluation
design permits, and define genuine and impostor pairs before running tests.

For a fixed, documented similarity threshold, record each pair's ground-truth
label, measured score, decision, and measured latency. Compute:

- Genuine Match Rate: correctly matched genuine comparisons divided by all
  genuine comparisons.
- False Acceptance Rate: impostor comparisons incorrectly matched divided by
  all impostor comparisons.
- False Rejection Rate: genuine comparisons incorrectly rejected divided by
  all genuine comparisons.

Report dataset population and composition, pair counts, threshold, exclusions,
and the evaluation date with every result. Do not infer security from a single
threshold or report scores from synthetic examples as measured accuracy.

For latency, report preprocessing time, AWS request time, and total
recognition time separately. Report p50, p95, and p99 only with the underlying
sample count and enough observations for tail percentiles to be meaningful;
otherwise mark them as illustrative or omit them. Normal automated tests use
mocked Rekognition responses and are not evaluation measurements.
