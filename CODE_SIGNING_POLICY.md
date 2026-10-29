# Code signing policy

Current status: unsigned. No SignPath subscription or certificate is claimed.
If accepted, the attribution will be: "Free code signing provided by SignPath.io,
certificate by SignPath Foundation". It will be added to the download/release
page when that service is actually in use.

| Role | Member | Responsibility |
| --- | --- | --- |
| Author / maintainer | Nizan Shtelman ([the-Otomator](https://github.com/the-Otomator)) | Source and build maintenance |
| Reviewer | Nizan Shtelman | Reviews outside contributions and build changes |
| Release/signing approver | Nizan Shtelman | Manually approves each signing request |

All people with repository/signing write access must use MFA for GitHub and
SignPath. Nizan must confirm account MFA and configure the SignPath roles before
submitting the application; this document is a policy, not an account audit.

Only this project's own executable built by GitHub Actions from a reviewed
version tag may be submitted. No private product binaries, upstream dependency
binaries for separate signing, or replacement local builds. Dependency licenses
must accompany the bundle. Product name/version metadata must match this
project and tag. Each signing request needs manual approval. The disabled
SignPath job requires a protected `code-signing` environment as an additional
release gate; Nizan must configure its required reviewer before enabling it.

Privacy: this program transfers information only to the consent server and
branding-image hosts explicitly chosen by the installer/operator, as detailed
in [README](README.md#privacy-and-consent). Signing is not consent to connect.
Provider approval does not certify the external broker or a deployment.

Certum fallback: only Nizan signs on his own PC, using SimplySign Desktop and
the mobile authorization flow. The repository contains no signing credentials.
The signed result has a different SHA-256 and must be reviewed separately; it
does not replace an existing pinned unsigned release asset.
