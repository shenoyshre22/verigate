# CI/CD

The GitHub Actions workflow in `.github/workflows/ci-cd.yml` runs backend
tests, frontend lint/tests/build, and AWS SAM template validation on pull
requests and pushes to `main`.

On a push to `main`, it deploys the SAM backend and starts a release for the
connected Amplify frontend. The frontend job is intentionally skipped until
the `frontend/` directory from `samreen/frontend` is merged into `main`.

## Required GitHub configuration

Create these repository or environment values:

- `AWS_REGION` variable (optional; defaults to `us-east-1`).
- `AWS_ENVIRONMENT` variable (optional; defaults to `dev`).
- `AWS_DEPLOY_ROLE_ARN` secret containing an IAM role trusted by the GitHub
  Actions OIDC provider.
- `AMPLIFY_APP_ID` variable after the Amplify app is connected to this
  repository.
- `AMPLIFY_BRANCH_NAME` variable (optional; defaults to `main`).

The deployment role must allow CloudFormation/SAM deployment, the required
S3 artifact operations, Lambda/API Gateway updates, IAM role creation or
pass-role as appropriate, and `amplify:StartJob` on the configured app.
Restrict the role trust policy to this repository and the `main` branch.

The current backend stores face references through a local directory
configuration, so the deployed health endpoint is immediately usable while
face-reference storage is wired to AWS. Do not enable production face
verification until that provider is configured with private AWS storage.
