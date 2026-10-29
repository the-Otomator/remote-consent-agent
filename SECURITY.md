# Security

Version 1.x receives security fixes while maintained. Report a suspected flaw
using this repository's private vulnerability reporting feature when available.
If it is unavailable, open an issue requesting a private contact channel without
including exploit details, access tokens, keys, device IDs or customer data.

Do not test against someone else's device, service or consent broker. Reproduce
with synthetic data on loopback. Include the version, expected consent boundary,
and a minimal reproduction. Acknowledge that the component requires a compatible
broker: it cannot remove access granted by unrelated remote tools.

Keep public signing/update keys separate from device keys. No UI or network
error may authorize a connection. Never add telemetry containing tokens,
private keys, enrollment configuration or user screenshots.
