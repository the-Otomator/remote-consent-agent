# Build, install and reproduce

Use Windows 10/11 x64 and Python 3.12. Official CI uses `windows-2022` and records
Python version, installed package versions, source SHA and executable SHA-256.

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -r support-windows/requirements.txt
.venv\Scripts\python -m unittest discover -s support-windows -p 'test_*.py' -v
./support-windows/build.ps1 -Python "$PWD/.venv/Scripts/python.exe"
```

Output: `support-windows/dist/RemoteConsentAgent-unsigned.exe`. The build is
source-reproducible, not claimed bit-for-bit reproducible: PyInstaller, Python,
transitive dependencies and the Windows runner image can affect PE bytes.
Direct dependencies are pinned; CI retains `pip freeze` and bundled third-party
license files. Compare source tag, package inventory and build log before
comparing output hashes. A same-source rebuild may legitimately hash differently.

## Signed installation config

The operator creates an Ed25519-signed JSON envelope with exactly `config` and
`signature` (hex). Sign the UTF-8 bytes from `consent_client.canonical(config)`.
Deliver the public key separately through a trusted channel, never accept a
public key just because it is embedded in the same downloaded config.
Keep the private key outside this repository. The configuration has these fields:

```json
{
  "v": 1, "domain": "remote-consent-agent-config",
  "org_id": "00000000-0000-0000-0000-000000000001",
  "device_id": "00000000-0000-0000-0000-000000000002",
  "issued_at": 1800000000, "expires_at": 1800000600,
  "endpoint": "https://example.invalid/consent",
  "broker_public_key": "<64 lowercase hex characters, matching the trusted key>",
  "publisher": "<40 hex certificate thumbprint, or empty for isolated unsigned tests>",
  "update_source": "https://example.invalid/pinned-release.exe",
  "branding": {"organization_name": "Example organization", "organization_logo_url": "", "technicians": {}}
}
```

`technicians` maps technician UUIDs to `{"name":"Example technician","photo_url":""}`.
Names/photos from the signed config override network-provided branding, keyed
by actual technician ID. Unknown technicians display a generic label and no
photo. Configuration is valid at installation for at most 24 hours. Restart
re-verifies its signature without expiring an already-installed device.
HTTPS, ordinary certificate verification and no redirects protect broker calls.
The broker key authenticates install config; it does not introduce a new server
response signature requirement. Device wire envelopes retain their legacy
`jumpstart-support-consent` domain and all v1 fields for interoperability.

In an elevated Windows shell (after reviewing the configuration and privacy
policy), run the downloaded executable from outside the install directory:

```powershell
./RemoteConsentAgent-unsigned.exe --install 'C:\Program Files\RemoteConsentAgent' --config ./enrollment.json --config-key <trusted-public-key>
./RemoteConsentAgent-unsigned.exe --enroll
```

Enrollment prompts for organization/device UUIDs and the owner's access token
without echoing it. Both UUIDs must match the signed configuration. The broker
must implement owner enrollment, device poll/answer/grant/revoke/end and signed
unenroll/pause. No server software or account is included. Existing installations
under another service name are not automatically migrated or overwritten.

To uninstall, run `./RemoteConsentAgent-unsigned.exe --uninstall 'C:\Program Files\RemoteConsentAgent'`
as administrator. Wait for signed broker confirmation. The service updater only
accepts a newer Authenticode-valid executable with the configured certificate
thumbprint while idle, after the broker confirms its pause. Unsigned builds
cannot auto-update. Certificate rollover needs separately authorized config
rotation; do not weaken the publisher check.

## Manual Certum signing

Install SimplySign Desktop and the Windows SDK signtool. Nizan authenticates in
the desktop client with his mobile authorization code, downloads the exact CI
artifact and verifies its SHA-256, then runs `./sign-certum.ps1` with its path,
expected hash, certificate thumbprint and signtool path. No phone code or secret
is passed to this script. It verifies Authenticode after signing and prints the
new hash. Nothing is uploaded automatically.
