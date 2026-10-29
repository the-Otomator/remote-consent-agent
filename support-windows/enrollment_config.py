"""Offline, signed installation configuration. No server or private key bundled."""
import json
import re
import time
from urllib.parse import urlsplit
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from consent_client import canonical, display, identifier


def endpoint(value):
    if not isinstance(value, str) or len(value) > 2048:
        raise ValueError('invalid_endpoint')
    parsed = urlsplit(value)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment):
        raise ValueError('invalid_endpoint')
    return value


def verify_config(envelope, trusted_key, *, now=None, installing=True):
    """The installer obtains trusted_key separately through its operator channel."""
    if not isinstance(trusted_key, str) or not re.fullmatch('[a-f0-9]{64}', trusted_key):
        raise ValueError('invalid_config_key')
    if not isinstance(envelope, dict) or set(envelope) != {'config', 'signature'}:
        raise ValueError('invalid_configuration')
    config = envelope['config']
    if not isinstance(config, dict) or set(config) != {
        'v', 'domain', 'org_id', 'device_id', 'issued_at', 'expires_at',
        'endpoint', 'broker_public_key', 'publisher', 'update_source', 'branding'
    }:
        raise ValueError('invalid_configuration')
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(trusted_key)).verify(
        bytes.fromhex(envelope['signature']), canonical(config))
    if config['v'] != 1 or config['domain'] != 'remote-consent-agent-config':
        raise ValueError('invalid_configuration_domain')
    if config['broker_public_key'] != trusted_key:
        raise ValueError('config_key_mismatch')
    identifier(config['org_id'])
    identifier(config['device_id'])
    stamp = time.time() if now is None else now
    issued, expires = config['issued_at'], config['expires_at']
    if (type(issued) is not int or type(expires) is not int or issued >= expires
            or expires - issued > 86400 or issued > stamp + 60
            or (installing and expires <= stamp)):
        raise ValueError('configuration_expired')
    endpoint(config['endpoint'])
    endpoint(config['update_source'])
    if not isinstance(config['publisher'], str) or (config['publisher'] and not re.fullmatch('[a-fA-F0-9]{40}', config['publisher'])):
        raise ValueError('invalid_publisher')
    brand = config['branding']
    if not isinstance(brand, dict) or set(brand) != {'organization_name', 'organization_logo_url', 'technicians'}:
        raise ValueError('invalid_branding')
    if not display(brand['organization_name']) or display(brand['organization_name']) != brand['organization_name']:
        raise ValueError('invalid_branding')
    if brand['organization_logo_url']:
        endpoint(brand['organization_logo_url'])
    if not isinstance(brand['technicians'], dict) or len(brand['technicians']) > 1000:
        raise ValueError('invalid_branding')
    for tech_id, tech in brand['technicians'].items():
        identifier(tech_id)
        if not isinstance(tech, dict) or set(tech) != {'name', 'photo_url'} or not display(tech['name']) or display(tech['name']) != tech['name']:
            raise ValueError('invalid_technician')
        if tech['photo_url']:
            endpoint(tech['photo_url'])
    return config.copy()


def load_config(path, key, **kwargs):
    if path is None or path.stat().st_size > 262144:
        raise ValueError('signed_configuration_required')
    return verify_config(json.loads(path.read_text(encoding='utf-8-sig')), key, **kwargs)


def brand_snapshot(snapshot, config):
    """Identity comes only from the verified config, bound by technician UUID."""
    brand = config['branding']
    result = dict(snapshot, organization_name=brand['organization_name'])
    for field in ('requests', 'connections'):
        result[field] = []
        for raw in snapshot[field]:
            tech = brand['technicians'].get(raw['technician_auth_id'], {})
            result[field].append(dict(raw, organization_name=brand['organization_name'],
                organization_logo_url=brand['organization_logo_url'],
                technician_name=tech.get('name', 'Technician'),
                technician_photo_url=tech.get('photo_url', '')))
    return result
