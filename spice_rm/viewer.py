"""Strict connection-file generation and native viewer invocation."""
from pathlib import Path
import os
import re
import shutil
import subprocess
import sys

from .security import SecurityError, session_file


def viewer_text(profile, vmid, node, ticket):
    if not isinstance(ticket, dict) or ticket.get('type') != 'spice':
        raise SecurityError('Proxmox did not return a SPICE configuration.')
    if ticket.get('proxy') != f'http://{profile.peer_ip}:3128':
        raise SecurityError('SPICE proxy does not match the enrolled host.')
    host = ticket.get('host', '')
    match = re.fullmatch(r'pvespiceproxy:[a-f0-9]{8}:(\d+):([A-Za-z0-9_-]+)(?::(\d+))?::[a-f0-9]{40}', str(host))
    if not match or int(match[1]) != vmid or match[2] != node:
        raise SecurityError('SPICE ticket does not match the selected VM and node.')
    try: port = int(ticket.get('tls-port', 0))
    except (ValueError, TypeError): raise SecurityError('Invalid SPICE TLS port.') from None
    if not 1 <= port <= 65535 or match[3] is not None and int(match[3]) != port:
        raise SecurityError('Invalid SPICE TLS port.')
    ca = str(ticket.get('ca', '')).replace('\\n', '\n').replace('\r\n', '\n').strip()
    if ca != profile.ca_pem.replace('\r\n', '\n').strip():
        raise SecurityError('SPICE CA differs from the enrolled Proxmox CA.')
    fields = {'type':'spice', 'host':host, 'proxy':ticket['proxy'], 'tls-port':str(port),
              'password':ticket.get('password', ''), 'host-subject':ticket.get('host-subject', ''),
              'title':ticket.get('title', f'VM {vmid}'),
              'ca':profile.ca_pem.replace('\r\n', '\n').replace('\n', '\\n'),
              'delete-this-file':'1', 'disable-clipboard':'1', 'enable-usbredir':'0',
              'enable-smartcard':'0'}
    for key, value in fields.items():
        if not isinstance(value, str) or not value or len(value) > 32768 or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise SecurityError('Invalid SPICE field: ' + key)
    return '[virt-viewer]\n' + ''.join(f'{key}={value}\n' for key, value in fields.items())


def find_viewer(configured=''):
    if configured:
        path = Path(configured).expanduser().absolute()
        # A local setting, never taken from imported profiles.
        if not path.is_file() or path.name.lower() not in ('remote-viewer', 'remote-viewer.exe'):
            raise SecurityError('Choose the remote-viewer executable, not a command or shell script.')
        return str(path)
    found = shutil.which('remote-viewer')
    if found: return found
    candidates = [Path(os.environ.get('ProgramFiles', 'C:/Program Files')) / 'VirtViewer v11.0-256/bin/remote-viewer.exe',
                  Path('/Applications/RemoteViewer.app/Contents/MacOS/remote-viewer'),
                  Path('/opt/homebrew/bin/remote-viewer'), Path('/usr/local/bin/remote-viewer'),
                  Path('/opt/local/bin/remote-viewer')]
    if os.name == 'nt':
        root = Path(os.environ.get('ProgramFiles', 'C:/Program Files'))
        candidates.extend(root.glob('VirtViewer*/bin/remote-viewer.exe'))
    for path in candidates:
        if path.is_file(): return str(path)
    raise SecurityError('Remote Viewer was not found. Install a maintained SPICE client and choose its executable in Settings.')


def open_viewer(text, executable='', opened=None):
    command = find_viewer(executable)
    with session_file(text) as path:
        try:
            process = subprocess.Popen([command, str(path)], stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL, shell=False)
            if opened: opened()
            code = process.wait()
        except OSError:
            raise SecurityError('Could not start Remote Viewer. Check its executable in Settings.') from None
        if code: raise SecurityError('Remote Viewer could not connect. Retry for a fresh ticket; check SPICE and VPN connectivity.')
