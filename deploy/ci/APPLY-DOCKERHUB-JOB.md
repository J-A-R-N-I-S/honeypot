# Apply Docker Hub CI job

The PAT used by automation lacks the GitHub `workflow` scope, so
`.github/workflows/image.yml` cannot be updated over the API/git HTTPS push.

**One-time apply** (account with `workflow` scope or SSO-authorized classic PAT):

```bash
cp deploy/ci/desired-image.yml .github/workflows/image.yml
git add .github/workflows/image.yml
git commit -m "ci: add dockerhub job for Hub latest+sha12"
git push
```

Or in the GitHub UI: edit `.github/workflows/image.yml` on this branch and
replace its contents with `deploy/ci/desired-image.yml`.

Required Actions secrets: `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN`.
Job `dockerhub` skips cleanly when either secret is empty.
