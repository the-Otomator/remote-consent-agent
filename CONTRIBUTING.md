# Contributing

Open an issue describing the behavior, then submit a focused pull request.
Contributions are MIT licensed. Do not include private service implementation,
internal documentation, real endpoints, credentials, or customer data.

Run `python -m unittest discover -s support-windows -p "test_*.py" -v` on Windows
after installing the pinned requirements. Exercise both Hebrew and English
with `python support-windows/main.py --gallery <output-directory>`.

Changes must preserve explicit consent, device-bound Ed25519 envelopes, expiry,
scope restrictions, protected device keys, visible disconnect controls, and
fail-closed behavior. Build/dependency/workflow changes require special review.
Maintainers require MFA. Only the release approver creates version tags after
review; GitHub Actions builds the release. Never commit generated executables.
