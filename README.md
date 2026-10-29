# Remote Consent Agent

A small Windows 10/11 x64 consent component, maintained by Nizan Shtelman
([the-Otomator](https://github.com/the-Otomator)). MIT licensed, without commercial dual-licensing.

It shows who requests screen, terminal or file access in Hebrew (RTL) or English.
It signs explicit approve/deny decisions, supports a clearly requested standing
approval (30 days or until revoked), and keeps a visible connection bar with
Disconnect and Disconnect all. Standing approval can be revoked from the tray.
It never starts a silent remote connection: the external broker must enforce
the customer's consent and report every connection. This project contains no
remote-control engine, Mesh credentials, commercial service or private broker.
The tray has status and revocation controls; no request-help hook was present in
the extracted native component.

## Download

Download the explicitly **unsigned** Windows executable and `SHA256SUMS.txt` from
[Releases](https://github.com/the-Otomator/remote-consent-agent/releases).
Initial builds have no trusted Authenticode signature. Do not bypass an
organization's installation policy. Production/customer rollout requires an
approved signer and separate operational acceptance.

Releases are built by GitHub Actions from version tags. Never upload a locally
built executable as an official release. See [Build and installation](BUILD.md).

## Privacy and consent

The person installing this program explicitly configures its HTTPS server and
branding-image hosts. It sends organization/device identifiers, signed consent
decisions, presence and connection/grant identifiers to that server. It fetches
configured organization logos and technician photos (their hosts see the IP
address). The server operator's privacy policy applies to those configured
systems. No analytics, screen capture, file transfer or command execution is
implemented here. No information is sent to the maintainers by default.

The installation configuration is signed with the operator/broker's Ed25519 key;
its public key is delivered separately over the installer's trusted operator
channel. No default server is built in. Device private keys stay in the
LocalSystem service, machine-DPAPI encrypted inside a SYSTEM-only directory.
The interactive UI cannot read them. Timeout, unavailable UI, lock, malformed
messages and network errors never imply approval. A previous active connection
remains visible until the broker confirms it ended. The component needs a
compatible consent broker; it cannot enforce access on an unrelated remote tool.

Installation creates a Windows service, protected state and a sign-in tray entry.
Uninstallation sends a signed unenrollment request and waits for broker-confirmed
disconnection before removing the service and device key. If the broker is
unreachable, retry rather than deleting the key and implying access ended.

## Code signing policy

See [Code signing policy](CODE_SIGNING_POLICY.md). SignPath support is planned
and disabled pending approval; no provider has approved or signed this project.
See [Security](SECURITY.md), [Contributing](CONTRIBUTING.md) and
[third-party notices](THIRD_PARTY_NOTICES.md).
