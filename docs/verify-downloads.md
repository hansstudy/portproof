# Verify this download

This artifact is **not Authenticode-signed**. Authenticode requires a paid code-signing
certificate, which is deferred until a tool shows traction, so Windows SmartScreen will show an
"unrecognized app" warning on the downloaded `PortProof.ps1`. PortProof is published only as a
GitHub Release; there is no package-manager channel. Until a certificate exists, every release
instead ships, next to `PortProof.ps1`:

- A `SHA256SUMS` file covering every release artifact, including the SBOM.
- A CycloneDX SBOM, `portproof-<version>.cdx.json`.
- A [Sigstore](https://www.sigstore.dev/) build-provenance attestation
  (`actions/attest-build-provenance`), proving the artifact came out of a known GitHub Actions
  build of a known commit, not a hand-uploaded file. The attestation bundle is also attached to
  the release as `portproof-<version>.intoto.jsonl`; it is not listed in `SHA256SUMS`, because it
  attests the files that `SHA256SUMS` covers.

## 1. Verify the checksum

Download `SHA256SUMS` from the same release as `PortProof.ps1`, then:

```powershell
Get-FileHash -Algorithm SHA256 .\PortProof.ps1
```

Compare the printed hash against the matching line in `SHA256SUMS`. They must match exactly.

## 2. Verify the build provenance attestation

Requires the [GitHub CLI](https://cli.github.com/) (`gh`):

```powershell
gh attestation verify .\PortProof.ps1 --owner hansstudy
```

A successful verification confirms the artifact was built by this repo's `release.yml` workflow,
from the tagged commit, and has not been modified since.

## Why this matters

Neither check replaces code review, and neither is a substitute for Authenticode once a
certificate exists - but together they are a stronger authenticity guarantee than an
Authenticode signature alone gives you, because they tie the artifact to the exact source commit
and build log, not just to a signing identity. See
`https://github.com/hansstudy/portproof/actions` for the build log referenced by the attestation.
