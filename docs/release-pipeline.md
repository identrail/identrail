# Release Pipeline

Identrail release automation is defined in:
- `.github/workflows/release.yml`

## Trigger Modes

- Tag push: `v*.*.*` (for example `v1.2.3`)
- Manual dispatch with:
  - `tag` (required)
  - `publish_images` (optional boolean; default `false` for manual dispatch)

## Required Configuration

- Keep the versioned `VITE_IDENTRAIL_API_URL` value in `deploy/docker/release-web.env`.
  This public HTTPS API base URL is baked into release web images.
- For manual runs with `publish_images=false`, image configuration is not required.
- Manual image backfills for historical tags that predate `deploy/docker/release-web.env`
  use the legacy release URL recorded by the workflow and attach that source in
  `release-web-build.txt`.

## What the Pipeline Publishes

1. Cross-platform binaries (`cli`, `server`, `worker`) as archives.
2. SHA-256 checksum manifest (`checksums.txt`).
3. Container images to GHCR:
   - `ghcr.io/<owner>/identrail-api:<tag>`
   - `ghcr.io/<owner>/identrail-worker:<tag>`
   - `ghcr.io/<owner>/identrail-web:<tag>`
4. Image digests and web build input metadata.
5. Auto-generated GitHub Release notes.

## Image Tag Rules

- Stable tags (`vX.Y.Z`) publish `<tag>` and `latest`.
- Pre-release tags (`vX.Y.Z-rc.1`, etc.) publish only `<tag>`.

## Recommended Usage

1. Merge all release-ready PRs into `dev`.
2. Create and push a SemVer tag:
   - `git tag v1.2.3`
   - `git push origin v1.2.3`
3. Verify release assets and image digests on GitHub Releases.

## Backfill Existing Tag Releases

If a SemVer tag already exists but no GitHub Release was published (for example `v1.0.0`):

1. Open **Actions** -> **Release** -> **Run workflow**.
2. Set:
   - `tag=v1.0.0`
   - `publish_images=false` (binary/checksum-only backfill), or `true` if GHCR image publish is required.
3. Run workflow and confirm release assets include archive files plus `checksums.txt`.
