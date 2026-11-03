"""Enrolled Tailscale peer identity; no public address/DNS fallback."""
import json
import os
from pathlib import Path
import shutil
import subprocess

from .security import SecurityError


def tailscale_executable():
    found = shutil.which('tailscale')
    if found: return found
    for path in (Path(os.environ.get('ProgramFiles', 'C:/Program Files')) / 'Tailscale/tailscale.exe',
                 Path('/Applications/Tailscale.app/Contents/MacOS/Tailscale')):
        if path.is_file(): return str(path)
    raise SecurityError('Tailscale CLI not found. Install Tailscale and make its CLI available.')


def tailnet_status():
    try:
        result = subprocess.run([tailscale_executable(), 'status', '--json'],
                                capture_output=True, text=True, check=True, timeout=12)
        if len(result.stdout) > 4 * 1024 * 1024: raise ValueError()
        return json.loads(result.stdout)
    except SecurityError: raise
    except (OSError, ValueError, subprocess.SubprocessError):
        raise SecurityError('Cannot read Tailscale status. Connect/sign in to Tailscale first.') from None


def verify_peer(profile, status):
    if not isinstance(status, dict) or status.get('BackendState') != 'Running':
        raise SecurityError('Tailscale is not connected.')
    peers = status.get('Peer', {}) or {}
    matches = [peer for peer in peers.values() if peer.get('ID') == profile.peer_id]
    if len(matches) != 1:
        raise SecurityError('Enrolled host identity is absent from this tailnet. Re-enrol after host re-registration.')
    peer = matches[0]
    if not peer.get('Online') or peer.get('Expired') or profile.peer_ip not in peer.get('TailscaleIPs', []):
        raise SecurityError('Enrolled host is offline, expired, or its Tailscale address changed.')
    return profile.peer_ip


def check_peer(profile):
    return verify_peer(profile, tailnet_status())
