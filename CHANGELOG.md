# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

### Changed

### Fixed

### Security

## [1.0.0-rc.1] - 2026-09-28

Release candidate for 1.0.0, published as a GitHub prerelease only (no channel).

### Added

- Initial release. PortProof takes a declared source-to-target-to-port requirement matrix (CSV or
  JSON) and probes exactly what it declares: a full TCP connect, a single zero-length UDP datagram,
  or (with `-Icmp`) one ICMP echo per distinct resolved target — nothing else, no ranges, no
  discovery.
- HTML, CSV, and JSON reports, each a pure function of the run's results; a gating exit code (0/1/2)
  so a change-window script can act on the outcome without parsing text.
- `-DryRun`: prints the probe list and a worst-case duration estimate; sends no probe and performs
  no name resolution.
- Bundled profile catalogue: Active Directory / domain controller reachability, SQL Server, and an
  RDP + WinRM management baseline, each sourced from public Microsoft documentation with a
  provenance sidecar.
- No telemetry, no credential handling, no outbound calls beyond the declared probes.

## [1.0.0] - 2026-09-25

### Added

- Initial release. PortProof takes a declared source-to-target-to-port requirement matrix (CSV or
  JSON) and probes exactly what it declares: a full TCP connect, a single zero-length UDP datagram,
  or (with `-Icmp`) one ICMP echo per distinct resolved target — nothing else, no ranges, no
  discovery.
- HTML, CSV, and JSON reports, each a pure function of the run's results; a gating exit code (0/1/2)
  so a change-window script can act on the outcome without parsing text.
- `-DryRun`: prints the probe list and a worst-case duration estimate; sends no probe and performs
  no name resolution.
- Bundled profile catalogue: Active Directory / domain controller reachability, SQL Server, and an
  RDP + WinRM management baseline, each sourced from public Microsoft documentation with a
  provenance sidecar.
- No telemetry, no credential handling, no outbound calls beyond the declared probes.

<!--
  On release: the release task re-dates this heading to the actual tag date if it differs from
  authoring, and adds a fresh empty [Unreleased] section above it. release.yml reads the section
  for the tag being released to populate the GitHub Release notes.
-->

[Unreleased]: https://github.com/hansstudy/portproof/compare/v1.0.0...HEAD
[1.0.0-rc.1]: https://github.com/hansstudy/portproof/releases/tag/v1.0.0-rc.1
[1.0.0]: https://github.com/hansstudy/portproof/releases/tag/v1.0.0
