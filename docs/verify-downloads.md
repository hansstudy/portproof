# Verify this download

This artifact is **not Authenticode-signed**. Authenticode requires a paid code-signing
certificate, which is deferred until a tool shows traction (H5) - Windows SmartScreen will
therefore show an "unrecognized app" warning on the downloaded `PortProof.ps1`, and a PowerShell
Gallery consumer has no Authenticode signature to check either. See
`TELEMETRY-AND-SUPPORT.md#verify-without-authenticode` for the umbrella policy this follows. Until
a certificate exists, every release instead ships:

- A `SHA256SUMS` file covering every release artifact, including the SBOM.
- A [Sigstore](https://www.sigstore.dev/) build-provenance attestation
  (`actions/attest-build-provenance`), proving the artifact came out of a known GitHub Actions
  build of a known commit, not a hand-uploaded file.

## 1. Verify the checksum

Download `SHA256SUMS` from the same release as `dist/PortProof.ps1`, then:

```powershell
Get-FileHash -Algorithm SHA256 .\PortProof.ps1
```

Compare the printed hash against the matching line in `SHA256SUMS`. They must match exactly.

## 2. Verify the build provenance attestation

Requires the [GitHub CLI](https://cli.github.com/) (`gh`):

```powershell
gh attestation verify dist/PortProof.ps1 --owner hansstudy
```

A successful verification confirms the artifact was built by this repo's `release.yml` workflow,
from the tagged commit, and has not been modified since.

## Why this matters

Neither check replaces code review, and neither is a substitute for Authenticode once a
certificate exists - but together they are a stronger authenticity guarantee than an
Authenticode signature alone gives you, because they tie the artifact to the exact source commit
and build log, not just to a signing identity. See
`https://github.com/hansstudy/portproof/actions` for the build log referenced by the attestation.
