"""Device-side consent protocol. No networking, UI or credentials in diagnostics."""
from __future__ import annotations

import json
import secrets
import time
import unicodedata
from dataclasses import dataclass
from typing import Callable
from uuid import UUID

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

TRANSPORTS = frozenset(("desktop", "terminal", "files"))
FIELDS = {
    "enroll": {"token", "public_key", "presence_required"}, "poll": set(),
    "answer": {"request_id", "technician_auth_id", "transport", "approved", "repeat", "scopes"},
    "grant": {"request_id", "technician_auth_id", "transport", "approved", "scopes", "duration", "customer_name"},
    "revoke": {"grant_id"}, "end": {"session_id"}, "unenroll": set(), "pause": set(),
}


def canonical(value: object) -> bytes:
    def check(item):
        if item is None or type(item) in (str, bool, int):
            return
        if type(item) is list:
            for entry in item:
                check(entry)
            return
        if type(item) is dict and all(type(key) is str for key in item):
            for entry in item.values():
                check(entry)
            return
        raise ValueError("invalid_canonical_type")
    check(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def identifier(value: str) -> str:
    if type(value) is not str or str(UUID(value)) != value:
        raise ValueError("invalid_identifier")
    return value


def display(value: object, limit: int = 240) -> str:
    """Bound plain text and remove controls, including directional overrides."""
    if not isinstance(value, str):
        return ""
    return "".join(c for c in value if not unicodedata.category(c).startswith("C"))[:limit].strip()


class DeviceSigner:
    def __init__(self, org: str, device: str, key: Ed25519PrivateKey,
                 clock: Callable = time.time, nonce: Callable = lambda: secrets.token_hex(32)):
        self.org, self.device = identifier(org), identifier(device)
        self.key, self.clock, self.nonce = key, clock, nonce

    @property
    def public_key(self):
        return self.key.public_key().public_bytes(serialization.Encoding.Raw,
                                                  serialization.PublicFormat.Raw).hex()

    def sign(self, action: str, **fields):
        if action not in FIELDS or set(fields) - FIELDS[action]:
            raise ValueError("invalid_message_fields")
        message = dict(v=1, domain="jumpstart-support-consent", org_id=self.org,
                       device_id=self.device, issued_at=int(self.clock()), nonce=self.nonce(),
                       action=action, **fields)
        return {"message": message, "signature": self.key.sign(canonical(message)).hex()}

    def enroll(self, token: str):
        if not isinstance(token, str) or len(token) != 64 or any(c not in "0123456789abcdef" for c in token):
            raise ValueError("invalid_bootstrap")
        return self.sign("enroll", token=token, public_key=self.public_key, presence_required=True)


@dataclass(frozen=True)
class Request:
    request_id: str
    technician: str
    transport: str
    purpose: str
    expires_at: int
    scopes: tuple[str, ...]
    fields: dict


class ConsentState:
    """Decisions require an explicit UI action. Poll and failures never approve."""
    def __init__(self, signer: DeviceSigner, send: Callable, clock: Callable = time.time):
        self.signer, self.send, self.clock = signer, send, clock
        self.requests: dict[str, Request] = {}
        self.connections: dict[str, dict] = {}
        self.grants: dict[str, dict] = {}
        self.consumed: set[str] = set()
        self.ending: set[str] = set()
        self.online = False
        self.error = ""
        self.organization_name = ""

    def bound(self, fields):
        if fields.get("org_id") != self.signer.org or fields.get("device_id") != self.signer.device:
            raise ValueError("message_rejected")

    def ingest(self, snapshot: dict):
        # Validate the whole response before changing any state. A failed poll
        # must retain the last known privacy bar until explicit ended evidence.
        if 'org_id' in snapshot or 'device_id' in snapshot:
            self.bound(snapshot)
        organization_name = display(snapshot.get('organization_name')) or self.organization_name
        requests = {}
        connections = {}
        grants = {}
        for raw in snapshot["requests"]:
            self.bound(raw)
            request_id = identifier(raw["request_id"])
            technician = identifier(raw["technician_auth_id"])
            transport, purpose, expires = raw["transport"], raw["purpose"], raw["expires_at"]
            if transport not in TRANSPORTS or purpose not in ("connect", "standing") or type(expires) is not int:
                raise ValueError("message_rejected")
            scopes = raw.get("scopes", [transport])
            if not isinstance(scopes, list) or not scopes or not set(scopes) <= TRANSPORTS:
                raise ValueError("message_rejected")
            if expires > self.clock() + 60:
                raise ValueError("clock_not_synchronized")
            if expires > self.clock() and request_id not in self.consumed:
                requests[request_id] = Request(request_id, technician, transport, purpose, expires,
                                                tuple(scopes), raw.copy())
        for raw in snapshot["connections"]:
            self.bound(raw)
            session = identifier(raw["id"])
            identifier(raw["technician_auth_id"])
            if raw["transport"] not in TRANSPORTS or raw["state"] not in ("issued", "active", "revoking", "ended", "failed"):
                raise ValueError("message_rejected")
            connections[session] = raw.copy()
        for raw in snapshot["grants"]:
            grant_id = identifier(raw["id"])
            if not set(raw["scopes"]) <= TRANSPORTS:
                raise ValueError("message_rejected")
            if raw["revoked"] is None and (raw["expires_at"] is None or raw["expires_at"] > self.clock()):
                grants[grant_id] = raw.copy()
        self.requests = requests
        # Absence does not prove termination; retain previously active entries.
        self.connections.update(connections)
        self.ending.difference_update(k for k, v in connections.items() if v["state"] == "ended")
        self.grants = grants
        self.organization_name = organization_name
        self.online, self.error = True, ""

    def poll(self):
        try:
            self.ingest(self.send(self.signer.sign("poll")))
        except Exception as failure:
            self.online = False
            code = str(failure)
            self.error = code if code in ("clock_not_synchronized", "message_rejected") else "poll_failed"
            self.requests.clear()
            raise

    @property
    def active(self):
        return [v for v in self.connections.values() if v["state"] in ("active", "revoking")]

    @property
    def current(self):
        return next((r for r in self.requests.values() if r.expires_at > self.clock()), None)

    def decide(self, request_id: str, approved: bool, *, interactive: bool,
               repeat: bool = False, scopes=None, duration=2592000, customer_name=""):
        request = self.requests.get(request_id)
        if (not self.online or not request or request.expires_at <= self.clock()
                or request_id in self.consumed or type(approved) is not bool
                or (approved and not interactive)):
            raise ValueError("decision_not_permitted")
        fields = dict(request_id=request.request_id, technician_auth_id=request.technician,
                      transport=request.transport, approved=approved)
        if request.purpose == "standing":
            chosen = list(scopes if scopes is not None else request.scopes)
            if not set(chosen) <= set(request.scopes) or (approved and not chosen):
                raise ValueError("scope_expansion")
            name = display(customer_name)
            if approved and (not name or duration not in (None, 2592000)):
                raise ValueError("invalid_grant")
            fields.update(scopes=chosen, duration=duration, customer_name=name)
            action = "grant"
        else:
            if type(repeat) is not bool:
                raise ValueError("invalid_repeat")
            fields["repeat"] = repeat if approved else False
            action = "answer"
        # Consume locally before sending: unknown network outcome must never
        # replay a customer click into a second decision.
        self.consumed.add(request_id)
        del self.requests[request_id]
        return self.send(self.signer.sign(action, **fields))

    def end(self, session: str):
        if session not in self.connections or self.connections[session]["state"] not in ("active", "revoking", "issued"):
            raise ValueError("invalid_session")
        self.ending.add(session)
        return self.send(self.signer.sign("end", session_id=session))

    def revoke(self, grant: str):
        if grant not in self.grants:
            raise ValueError("invalid_grant")
        self.ending.update(v["id"] for v in self.active if v.get("grant_id") == grant)
        return self.send(self.signer.sign("revoke", grant_id=grant))
