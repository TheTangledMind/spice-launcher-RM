import unittest
from unittest.mock import patch
from spice_rm import api, viewer
from spice_rm.profile import Profile
from spice_rm.security import SecurityError
from tests.test_security import sample


def ticket():
    return {'type':'spice', 'host':'pvespiceproxy:abcdef12:100:pve:61000::' + 'a'*40,
            'proxy':'http://100.80.1.2:3128', 'tls-port':61000, 'password':'ticket-value',
            'ca': sample()['ca_pem'].replace('\n', '\\n'), 'host-subject':'CN=pve.example.test',
            'title':'Test VM'}


class ViewerConfigTests(unittest.TestCase):
    def test_valid_ticket_uses_enrolled_proxy_and_disables_device_sharing(self):
        text = viewer.viewer_text(Profile.from_dict(sample()), 100, 'pve', ticket())
        self.assertIn('proxy=http://100.80.1.2:3128\n', text)
        self.assertIn('disable-clipboard=1\n', text)
        self.assertIn('enable-usbredir=0\n', text)

    def test_tampered_ticket_rejected(self):
        for changes in ({'proxy':'http://evil.test:3128'}, {'ca':'evil'}, {'password':'secret\nproxy=evil'},
                        {'host':ticket()['host'].replace(':100:', ':200:')},
                        {'host':ticket()['host'].replace(':pve:', ':other:')}, {'tls-port':'garbage'},
                        {'host-subject':''}, {'type':'vnc'}):
            with self.subTest(changes=changes), self.assertRaises(SecurityError):
                viewer.viewer_text(Profile.from_dict(sample()), 100, 'pve', dict(ticket(), **changes))


class ClientFlowTests(unittest.TestCase):
    def client(self, members):
        client = object.__new__(api.Client)
        client.profile = Profile.from_dict(sample())
        client.members = lambda: members
        return client

    def test_pool_removal_prevents_console_request(self):
        with self.assertRaises(SecurityError): self.client([]).connection_file(100)

    def test_stopped_machine_prevents_console_request(self):
        with self.assertRaises(SecurityError):
            self.client([dict(vmid=100, status='stopped')]).connection_file(100)

    def test_all_supported_displays_obtain_validated_viewer_file(self):
        for display in ('qxl', 'qxl2', 'qxl3', 'qxl4', 'virtio', 'virtio-gl', 'memory=128,type=virtio-gl'):
            client = self.client([dict(vmid=100, name='VM', node='pve', status='running')])
            calls = []
            def request(path, data=None):
                calls.append((path, data))
                if path.endswith('/config'): return {'vga':display}
                if path.endswith('/spiceproxy'): return ticket()
                raise AssertionError(path)
            client.request = request
            with self.subTest(display=display):
                text = client.connection_file(100)
                self.assertIn('password=ticket-value', text)
                self.assertEqual(calls[-1], ('/nodes/pve/qemu/100/spiceproxy', {'proxy':'100.80.1.2'}))


if __name__ == '__main__': unittest.main()
