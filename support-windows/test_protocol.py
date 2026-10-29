import copy
import time
import unittest
import uuid
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from consent_client import ConsentState, DeviceSigner, canonical, display
from enrollment_config import verify_config, brand_snapshot


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.now = int(time.time())
        self.org, self.device, self.tech, self.request = [str(uuid.uuid4()) for _ in range(4)]
        self.key = Ed25519PrivateKey.generate()
        self.signer = DeviceSigner(self.org, self.device, self.key, lambda: self.now, lambda: '0' * 64)
        self.sent = []
        self.state = ConsentState(self.signer, lambda e: self.sent.append(e) or {}, lambda: self.now)
        self.raw = dict(org_id=self.org, device_id=self.device, request_id=self.request,
            technician_auth_id=self.tech, transport='desktop', purpose='connect', expires_at=self.now + 60)
        self.snapshot = dict(requests=[self.raw], connections=[], grants=[])
        self.state.ingest(self.snapshot)

    def test_wire_bytes_and_signature(self):
        e = self.signer.sign('poll')
        expected = ('{"action":"poll","device_id":"' + self.device + '","domain":"jumpstart-support-consent","issued_at":'
            + str(self.now) + ',"nonce":"' + '0' * 64 + '","org_id":"' + self.org + '","v":1}').encode()
        self.assertEqual(canonical(e['message']), expected)
        self.key.public_key().verify(bytes.fromhex(e['signature']), expected)

    def test_all_signed_envelope_actions(self):
        fields = dict(enroll=dict(token='1'*64, public_key=self.signer.public_key, presence_required=True), poll={},
            answer=dict(request_id=self.request, technician_auth_id=self.tech, transport='desktop', approved=False, repeat=False),
            grant=dict(request_id=self.request, technician_auth_id=self.tech, transport='desktop', approved=True, scopes=['desktop'], duration=None, customer_name='Example'),
            revoke=dict(grant_id=str(uuid.uuid4())), end=dict(session_id=str(uuid.uuid4())), unenroll={}, pause={})
        for action, payload in fields.items():
            e = self.signer.sign(action, **payload)
            self.key.public_key().verify(bytes.fromhex(e['signature']), canonical(e['message']))
            self.assertEqual(e['message']['domain'], 'jumpstart-support-consent')

    def test_approval_requires_interaction(self):
        with self.assertRaises(ValueError): self.state.decide(self.request, True, interactive=False)
        self.assertEqual(self.sent, [])

    def test_denial_and_consumption(self):
        self.state.decide(self.request, False, interactive=False, repeat=True)
        self.assertFalse(self.sent[0]['message']['approved'])
        self.assertFalse(self.sent[0]['message']['repeat'])
        with self.assertRaises(ValueError): self.state.decide(self.request, True, interactive=True)

    def test_timeout(self):
        self.now += 60
        with self.assertRaises(ValueError): self.state.decide(self.request, True, interactive=True)

    def test_failed_poll_cannot_approve(self):
        self.state.send = lambda _: (_ for _ in ()).throw(OSError())
        with self.assertRaises(OSError): self.state.poll()
        self.assertFalse(self.state.online)
        self.assertIsNone(self.state.current)

    def test_foreign_identity(self):
        raw = dict(self.raw, device_id=str(uuid.uuid4()))
        with self.assertRaises(ValueError): self.state.ingest(dict(self.snapshot, requests=[raw]))

    def test_standing_scope_and_revoke(self):
        self.state.ingest(dict(self.snapshot, requests=[dict(self.raw, purpose='standing', scopes=['desktop'])]))
        with self.assertRaises(ValueError):
            self.state.decide(self.request, True, interactive=True, scopes=['files'], customer_name='Example')
        self.state.decide(self.request, True, interactive=True, scopes=['desktop'], duration=None, customer_name='Example')
        grant = str(uuid.uuid4())
        self.state.grants[grant] = dict(id=grant)
        self.state.revoke(grant)
        self.assertEqual(self.sent[-1]['message']['action'], 'revoke')

    def test_active_connection_retained_until_ended(self):
        session = str(uuid.uuid4())
        connection = dict(self.raw, id=session, state='active')
        self.state.ingest(dict(requests=[], grants=[], connections=[connection]))
        self.state.end(session)
        self.state.ingest(dict(requests=[], grants=[], connections=[]))
        self.assertEqual(len(self.state.active), 1)
        self.assertIn(session, self.state.ending)
        self.state.ingest(dict(requests=[], grants=[], connections=[dict(connection, state='ended')]))
        self.assertEqual(self.state.active, [])
        self.assertNotIn(session, self.state.ending)

    def test_plain_display(self):
        self.assertEqual(display('A\u202e\x00B'), 'AB')
        self.assertEqual(len(display('x' * 300)), 240)


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.now = int(time.time())
        self.key = Ed25519PrivateKey.generate()
        self.pub = self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        self.tech = str(uuid.uuid4())
        self.config = dict(v=1, domain='remote-consent-agent-config', org_id=str(uuid.uuid4()), device_id=str(uuid.uuid4()),
            issued_at=self.now, expires_at=self.now + 600, endpoint='https://example.invalid/consent',
            broker_public_key=self.pub, publisher='', update_source='https://example.invalid/update.exe',
            branding=dict(organization_name='Example', organization_logo_url='', technicians={self.tech: dict(name='Example technician', photo_url='')}))

    def envelope(self):
        return dict(config=copy.deepcopy(self.config), signature=self.key.sign(canonical(self.config)).hex())

    def verify(self, e=None, **kwargs):
        return verify_config(e or self.envelope(), self.pub, now=self.now, **kwargs)

    def test_signed_config(self): self.assertEqual(self.verify(), self.config)

    def test_tamper_and_wrong_key(self):
        e = self.envelope()
        e['config']['endpoint'] = 'https://other.invalid/'
        with self.assertRaises(InvalidSignature): self.verify(e)
        with self.assertRaises(InvalidSignature): verify_config(self.envelope(), '0'*64, now=self.now)

    def test_expired_and_future(self):
        self.config['expires_at'] = self.now
        with self.assertRaises(ValueError): self.verify()
        self.config.update(issued_at=self.now + 100, expires_at=self.now + 200)
        with self.assertRaises(ValueError): self.verify()

    def test_expiration_checked_at_install_only(self):
        self.config.update(issued_at=self.now - 1000, expires_at=self.now - 100)
        self.assertEqual(self.verify(installing=False), self.config)
        with self.assertRaises(ValueError): self.verify()

    def test_unsafe_endpoints(self):
        for url in ['http://example.invalid/', 'https://user:pass@example.invalid/', 'https://example.invalid/?token=secret']:
            self.config['endpoint'] = url
            with self.assertRaises(ValueError): self.verify()

    def test_branding_bound_by_tech_id(self):
        c = self.verify()
        result = brand_snapshot(dict(requests=[dict(technician_auth_id=self.tech, technician_name='Spoofed')], connections=[]), c)
        self.assertEqual(result['requests'][0]['technician_name'], 'Example technician')
        result = brand_snapshot(dict(requests=[dict(technician_auth_id=str(uuid.uuid4()), technician_name='Spoofed')], connections=[]), c)
        self.assertEqual(result['requests'][0]['technician_name'], 'Technician')

    def test_key_and_domain_binding(self):
        self.config['broker_public_key'] = '0'*64
        with self.assertRaises(ValueError): self.verify()
        self.config['broker_public_key'] = self.pub
        self.config['domain'] = 'other'
        with self.assertRaises(ValueError): self.verify()


if __name__ == '__main__': unittest.main()
