"""OS-native credentials and explicitly private per-session storage."""
from contextlib import contextmanager
import os
from pathlib import Path
import subprocess
import sys
import tempfile


class SecurityError(Exception):
    """Safe-to-display operational/security error. Never include secrets."""


def config_dir():
    if sys.platform == 'win32':
        base = Path(os.environ.get('LOCALAPPDATA', str(Path.home() / 'AppData' / 'Local')))
    elif sys.platform == 'darwin':
        base = Path.home() / 'Library' / 'Application Support'
    else:
        base = Path(os.environ.get('XDG_CONFIG_HOME', str(Path.home() / '.config')))
    return base / 'spice-launcher-rm'


def protect_directory(path):
    path = Path(path).absolute()
    if path.is_symlink(): raise SecurityError('Private directory cannot be a symbolic link.')
    if os.name == 'nt':
        # SID, not a display username, avoids localisation and name ambiguity.
        result = subprocess.run(['whoami.exe', '/user', '/fo', 'csv', '/nh'], capture_output=True, text=True, check=True, timeout=10)
        import csv
        sid = next(csv.reader([result.stdout.strip()]))[1]
        import re
        if not re.fullmatch(r'S-1-[0-9-]+', sid): raise SecurityError('Cannot identify Windows user SID.')
        subprocess.run(['icacls.exe', str(path), '/inheritance:r', '/grant:r', f'*{sid}:(OI)(CI)F'],
                       check=True, capture_output=True, timeout=10)
    else:
        if path.stat().st_uid != os.getuid(): raise SecurityError('Private directory is not owned by you.')
        path.chmod(0o700)


def private_write(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    protect_directory(path.parent)
    fd, tmp = tempfile.mkstemp(prefix='.new-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as stream:
            stream.write(text)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)


@contextmanager
def session_file(text, base=None):
    # mkdtemp creates the directory before any secret is written. On Windows
    # replace inherited access before creating the connection file.
    base = base or os.environ.get('XDG_RUNTIME_DIR') or tempfile.gettempdir()
    with tempfile.TemporaryDirectory(prefix='spice-rm-', dir=base) as directory:
        path = Path(directory)
        protect_directory(path)
        target = path / 'console.vv'
        private_write(target, text)
        yield target


def require_native_backend(backend):
    name = type(backend).__module__ + '.' + type(backend).__name__
    allowed = {
        'keyring.backends.Windows.WinVaultKeyring',
        'keyring.backends.macOS.Keyring',
        'keyring.backends.SecretService.Keyring',
        'keyring.backends.libsecret.Keyring',
        'keyring.backends.kwallet.DBusKeyring',
        'keyring.backends.kwallet.DBusKeyringKWallet4',
    }
    if name not in allowed:
        raise SecurityError('A native OS credential store is required. Unlock/configure Keychain, Credential Manager, Secret Service or KWallet. No file fallback is used.')
    return backend


def native_backend():
    import keyring
    # Select explicitly; never accept a third-party/plaintext fallback chain.
    if sys.platform == 'win32':
        from keyring.backends.Windows import WinVaultKeyring
        backend = WinVaultKeyring()
    elif sys.platform == 'darwin':
        from keyring.backends.macOS import Keyring
        backend = Keyring()
    else:
        candidates = []
        for module, cls in (('SecretService', 'Keyring'), ('kwallet', 'DBusKeyring'), ('libsecret', 'Keyring')):
            try:
                import importlib
                obj = getattr(importlib.import_module('keyring.backends.' + module), cls)()
                if obj.priority > 0: candidates.append(obj)
            except Exception:
                continue
        if not candidates: raise SecurityError('No unlocked Linux secret service is available. Start/unlock your desktop keyring.')
        backend = candidates[0]
    return require_native_backend(backend)


def get_secret(profile):
    try:
        value = native_backend().get_password('spice-launcher-rm', profile.credential_key)
    except SecurityError: raise
    except Exception: raise SecurityError('Could not read the OS credential store. Unlock it and retry.') from None
    if not value: raise SecurityError('No token saved for this profile. Open Settings.')
    return validate_secret(value)


def validate_secret(value):
    if not isinstance(value, str) or not 8 <= len(value) <= 512 or any(ord(c) < 33 or ord(c) > 126 for c in value):
        raise SecurityError('Invalid API token secret.')
    return value


def set_secret(profile, value):
    value = validate_secret(value)
    try: native_backend().set_password('spice-launcher-rm', profile.credential_key, value)
    except SecurityError: raise
    except Exception: raise SecurityError('Could not save to the OS credential store.') from None
