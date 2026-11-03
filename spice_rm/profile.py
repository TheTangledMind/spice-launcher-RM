"""Public enrolment data; credentials and executable paths never belong here."""
from dataclasses import dataclass, asdict
import hashlib
import ipaddress
import json
from pathlib import Path
import re


@dataclass(frozen=True)
class Profile:
    version: int
    label: str
    peer_id: str
    peer_ip: str
    tls_name: str
    pool: str
    token_id: str
    ca_pem: str

    @classmethod
    def from_dict(cls, data):
        if not isinstance(data, dict) or set(data) != set(cls.__dataclass_fields__):
            raise ValueError('Invalid enrolment fields. Use the public profile exported by the host tool.')
        if type(data['version']) is not int or data['version'] != 1:
            raise ValueError('Unsupported profile version.')
        for key, value in data.items():
            if key == 'version': continue
            if not isinstance(value, str) or not value or len(value) > (16384 if key == 'ca_pem' else 253):
                raise ValueError('Invalid profile value: ' + key)
            if key != 'ca_pem' and any(ord(c) < 32 or ord(c) == 127 for c in value):
                raise ValueError('Control character in profile.')
        ip = ipaddress.ip_address(data['peer_ip'])
        if ip.version != 4 or ip not in ipaddress.ip_network('100.64.0.0/10'):
            raise ValueError('Use the enrolled host IPv4 Tailscale address (100.64.0.0/10).')
        if not re.fullmatch(r'[A-Za-z0-9_-]{3,100}', data['peer_id']):
            raise ValueError('Invalid stable Tailscale peer ID.')
        hostname = data['tls_name']
        if not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', part) for part in hostname.split('.')):
            raise ValueError('Invalid TLS hostname.')
        if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,63}', data['pool']):
            raise ValueError('Invalid resource pool.')
        if not re.fullmatch(r'[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+![A-Za-z][A-Za-z0-9_.-]+', data['token_id']):
            raise ValueError('Invalid API token ID.')
        if not data['ca_pem'].startswith('-----BEGIN CERTIFICATE-----\n') or '\x00' in data['ca_pem']:
            raise ValueError('Invalid CA certificate PEM.')
        return cls(**data)

    @classmethod
    def load(cls, path):
        with Path(path).open('rb') as stream:
            raw = stream.read(65537)
        if len(raw) > 65536: raise ValueError('Profile exceeds 64 KiB.')
        return cls.from_dict(json.loads(raw))

    @property
    def ca_fingerprint(self):
        # File fingerprint is reproducible with sha256sum/shasum/Get-FileHash.
        return hashlib.sha256(self.ca_pem.encode('utf-8')).hexdigest()

    @property
    def credential_key(self):
        identity = '\0'.join((self.peer_id, self.tls_name, self.token_id, self.ca_fingerprint, self.pool))
        return hashlib.sha256(identity.encode()).hexdigest()

    def to_dict(self):
        return asdict(self)
