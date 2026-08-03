# Changelog

All notable changes to SiberKapan are documented in this file.

## 2026-08-03

### Added
- **SMTP Honeypot** — HoneypotKapan now emulates 11 services (previously 10), adding SMTP with AUTH LOGIN/PLAIN credential capture and open-relay (MAIL FROM/RCPT TO) detection.
- **Malware Sample Capture** — The SSH honeypot now safely captures malware samples attackers attempt to download. Files are never written to disk or executed; only a SHA256 fingerprint and size are recorded, retrieved through an SSRF-protected fetcher (public-IP-only resolution, DNS-rebinding safe, 5MB / 8s limits, max 3 redirects).
- **MalwareBazaar Enrichment** — Captured hashes are automatically checked against abuse.ch MalwareBazaar every 2 hours, tagging known malware families.
- **Sigma Rule Export** — New `/api/v1/export/sigma` endpoint generates SIEM-agnostic Sigma detection rules from SiberKapan's own-source threat data (Splunk, Elastic, Sentinel, QRadar compatible via pySigma).
- **Malware Samples Showcase** — New public page at `/malware-samples` listing captured samples with source IP, command, and MalwareBazaar status.
- **IP Detail Page — Captured Samples** — `/ip/<address>` now shows any malware samples associated with that IP, linked to MalwareBazaar.

### Fixed
- The SSH honeypot previously rejected all authentication attempts, which — at the SSH protocol level — prevented any post-authentication command capture. Authentication is now accepted (a standard medium-interaction honeypot pattern, consistent with projects like Cowrie) so attacker commands, including download attempts, can be observed and logged. The attacker is never given a real shell or filesystem access — all interaction is simulated.
- Added dual RSA/ECDSA host keys to the SSH honeypot, fixing a host-key algorithm mismatch ("Couldn't agree a host key algorithm") with modern SSH clients (PuTTY, OpenSSH 8.8+) that reject legacy `ssh-rsa` signatures.
- Fixed a character-echo bug in the honeypot's simulated shell where typed input was invisible to interactive terminal clients.
- The honeypot reporter now sends a report immediately when a malware sample is captured, instead of waiting for the standard 3-hit corroboration threshold — sample data was previously at risk of never reaching the central feed on low-interaction sessions.

## Earlier

See commit history for changes prior to this changelog's introduction.
