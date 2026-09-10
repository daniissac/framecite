# Releasing FrameCite

FrameCite publishes to PyPI from GitHub Actions with OpenID Connect trusted publishing. Do not create or store a long-lived PyPI API token.

## One-time PyPI setup

Before the first release, sign in to PyPI and add a pending GitHub publisher with these exact values:

- PyPI project name: `framecite`
- GitHub owner: `daniissac`
- GitHub repository: `framecite`
- Workflow filename: `publish.yml`
- Environment name: `pypi`

Also create a protected GitHub Actions environment named `pypi`. Requiring approval for that environment is recommended so publishing cannot happen merely because a GitHub release was created accidentally.

A pending publisher does not reserve the project name. Recheck that `framecite` is available immediately before the first release.

## Release checklist

1. Merge the intended release commit into `main` and confirm CI passes.
2. Confirm `pyproject.toml` and `src/framecite/__init__.py` contain the same version.
3. Confirm the version has not already been published to PyPI; published files and versions cannot be replaced.
4. Build and verify locally:

   ```bash
   python -m pip install -e ".[dev]"
   ruff check .
   ruff format --check .
   pytest
   python -m build
   ```

5. Install the built wheel in a clean environment and run:

   ```bash
   framecite --version
   framecite --help
   ```

6. Create a signed tag such as `v0.2.0` from the verified `main` commit and push it.
7. Create and publish the matching GitHub release. Publishing the release triggers `.github/workflows/publish.yml`.
8. Approve the `pypi` environment deployment if protection rules require it.
9. Confirm both distributions appear on PyPI and test `uvx framecite --version` against the published package.

If publication fails after PyPI accepts either distribution, do not reuse the version. Diagnose the failure and release a new patch version.
