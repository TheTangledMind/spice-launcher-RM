import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from spice_rm import profile, security, network


def sample():
    return dict(version=1, label='Lab host', peer_id='nTestPeer123', peer_ip='100.80.1.2',
                tls_name='pve.example.test', pool='spice-rm', token_id='spice-rm@pve!desktop',
                ca_pem='-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n')


class ProfileTests(unittest.TestCase):
    def test_profile_rejects_injected_commands_and_non_overlay_addresses(self):
        for changes in ({'peer_ip':'8.8.8.8'}, {'peer_ip':'192.168.1.1'},
                        {'tls_name':'pve.test/path'}, {'pool':'../other'},
                        {'token_id':'user@pve!token\r\nX: evil'}, {'viewer':'evil.exe'},
                        {'peer_id':''}, {'version':2}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                profile.Profile.from_dict(dict(sample(), **changes))

    def test_profile_roundtrip_does_not_embed_secret(self):
        p = profile.Profile.from_dict(sample())
        self.assertEqual(p.to_dict(), sample())
        self.assertEqual(len(p.ca_fingerprint), 64)
        self.assertNotIn('secret', json.dumps(p.to_dict()))


class PrivateStorageTests(unittest.TestCase):
    def test_private_file_cleanup_after_error(self):
        with tempfile.TemporaryDirectory() as root:
            path = None
            with self.assertRaisesRegex(RuntimeError, 'viewer failed'):
                with security.session_file('ticket', base=Path(root)) as path:
                    self.assertEqual(path.read_text(), 'ticket')
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                    self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
                    raise RuntimeError('viewer failed')
            self.assertFalse(path.exists())

    def test_plaintext_and_chained_keyring_backends_rejected(self):
        for name in ('keyrings.alt.file.PlaintextKeyring', 'keyring.backends.chainer.ChainerBackend', 'keyring.backends.fail.Keyring'):
            module, cls = name.rsplit('.', 1)
            backend = type(cls, (), {'__module__': module})()
            with self.subTest(name=name), self.assertRaises(security.SecurityError):
                security.require_native_backend(backend)


class TailnetTests(unittest.TestCase):
    def status(self):
        return {'BackendState':'Running', 'Peer': {'nodekey:test':{
            'ID':'nTestPeer123', 'TailscaleIPs':['100.80.1.2'], 'Online':True, 'Expired':False}}}

    def test_peer_identity_is_required_not_merely_tailnet_address(self):
        p = profile.Profile.from_dict(sample())
        self.assertEqual(network.verify_peer(p, self.status()), '100.80.1.2')
        for change in ({'ID':'nAttacker'}, {'Online':False}, {'Expired':True}, {'TailscaleIPs':['100.80.2.3']}):
            state = self.status()
            state['Peer']['nodekey:test'].update(change)
            with self.subTest(change=change), self.assertRaises(security.SecurityError):
                network.verify_peer(p, state)
        with self.assertRaises(security.SecurityError):
            network.verify_peer(p, dict(self.status(), BackendState='Stopped'))


if __name__ == '__main__': unittest.main()
