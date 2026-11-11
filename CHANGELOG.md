# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.1] - 2026-11-11

### Security

- Plugin binaries are now built with the latest stable Go release. 1.0.0 was built with Go 1.26.0,
  which has known vulnerabilities in the Go standard library (`net/http`, `crypto/tls`,
  `crypto/x509`). Upgrade from 1.0.0.

### Changed

- CI and the release workflow use the latest stable Go and run `govulncheck`; a release is not
  published when it finds a vulnerability.

## [1.0.0] - 2026-11-11

Initial release.

### Added

- `/shodan` slash command and a bot account that posts the results.
- IP list management: upload from the System Console or by direct message, add and remove single IPs.
  Only public IP addresses are accepted.
- Scheduled lookups every N days that report only the IPs that changed, with `results.json` attached.
- On-demand lookups for one IP or the whole list.
- Active Shodan scans for one IP or the whole list, with a credit check before whole-list scans.
- Multiple Shodan API keys, used in turn, with key validation before each run.
- Access control: system admins, optional team admin access, and users added by a system admin.
- Results are posted only in private channels and direct messages.
