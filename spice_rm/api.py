"""Proxmox HTTPS over a verified overlay address, with original TLS identity."""
import http.client
import json
import socket
import ssl
from urllib.parse import quote, urlencode

from .network import check_peer
from .security import SecurityError, get_secret
from .viewer import viewer_text


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, peer_ip, tls_name, context, port=8006):
        super().__init__(tls_name, port=port, timeout=12, context=context)
        self.peer_ip = peer_ip

    def connect(self):
        # No DNS lookup of the certificate name: the enrolled peer is the
        # network destination; the certificate name is the authentication ID.
        raw = socket.create_connection((self.peer_ip, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


class Client:
    def __init__(self, profile):
        self.profile = profile
        self.secret = get_secret(profile)
        try:
            self.context = ssl.create_default_context(cadata=profile.ca_pem)
            self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        except (ValueError, ssl.SSLError):
            raise SecurityError('The enrolled CA certificate is invalid. Re-export a profile from your host.') from None

    def request(self, path, data=None):
        peer_ip = check_peer(self.profile)
        connection = PinnedHTTPSConnection(peer_ip, self.profile.tls_name, self.context)
        body = None if data is None else urlencode(data).encode('ascii')
        headers = {'Authorization': f'PVEAPIToken={self.profile.token_id}={self.secret}',
                   'Accept':'application/json', 'Content-Type':'application/x-www-form-urlencoded'}
        try:
            connection.request('GET' if data is None else 'POST', '/api2/json' + path, body, headers)
            response = connection.getresponse()
            # No redirect following, including same-origin redirects.
            if 300 <= response.status < 400: raise SecurityError('Proxmox attempted a redirect; connection refused.')
            if response.status == 401: raise SecurityError('API token rejected or expired. Update Settings.')
            if response.status == 403: raise SecurityError('Permission denied. Check both account and token pool grants.')
            if response.status >= 400: raise SecurityError(f'Proxmox returned HTTP {response.status}. Check the VM and host configuration.')
            raw = response.read(2 * 1024 * 1024 + 1)
            if len(raw) > 2 * 1024 * 1024: raise SecurityError('Oversized API response refused.')
            return json.loads(raw)['data']
        except ssl.SSLCertVerificationError:
            raise SecurityError('TLS certificate verification failed. Check the enrolled CA and original certificate hostname.') from None
        except (OSError, http.client.HTTPException):
            raise SecurityError('Cannot connect to the enrolled Proxmox host through Tailscale.') from None
        except (ValueError, KeyError, TypeError):
            raise SecurityError('Unexpected response from Proxmox.') from None
        finally:
            connection.close()

    def members(self):
        pools = self.request('/pools?' + urlencode({'poolid':self.profile.pool, 'type':'qemu'}))
        if not isinstance(pools, list) or len(pools) != 1 or pools[0].get('poolid') != self.profile.pool:
            raise SecurityError('Configured pool is absent or inaccessible.')
        rows = []
        for member in pools[0].get('members', []):
            if member.get('type') != 'qemu': continue
            vmid = member.get('vmid')
            node = member.get('node', '')
            import re
            if type(vmid) is not int or not 100 <= vmid <= 999999999 or not re.fullmatch(r'[A-Za-z0-9_-]+', node):
                raise SecurityError('Invalid VM identity returned by Proxmox.')
            rows.append(dict(vmid=vmid, node=node, name=str(member.get('name') or f'VM {vmid}'),
                             status=member.get('status', 'unknown')))
        return sorted(rows, key=lambda vm: vm['vmid'])

    def connection_file(self, vmid):
        vm = next((row for row in self.members() if row['vmid'] == vmid), None)
        if vm is None: raise SecurityError('VM is no longer enrolled in this pool. Refresh the menu.')
        if vm['status'] != 'running': raise SecurityError('Start this VM in Proxmox before connecting.')
        base = f'/nodes/{quote(vm["node"], safe="")}/qemu/{vmid}'
        config = self.request(base + '/config')
        options = dict(part.split('=', 1) if '=' in part else ('type', part)
                       for part in str(config.get('vga', '')).split(','))
        if options.get('type') not in {'qxl','qxl2','qxl3','qxl4','virtio','virtio-gl'}:
            raise SecurityError('Configure SPICE, VirtIO-GPU or VirGL in the VM Display settings.')
        ticket = self.request(base + '/spiceproxy', {'proxy':self.profile.peer_ip})
        return viewer_text(self.profile, vmid, vm['node'], ticket)
