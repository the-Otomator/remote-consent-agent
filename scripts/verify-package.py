"""Inspect the actual distributable before release publication."""
import hashlib
import json
import sys
import zipfile

with zipfile.ZipFile(sys.argv[1]) as package:
    names = package.namelist()
    assert 'RemoteConsentAgent-unsigned.exe' in names
    expected = package.read('SHA256SUMS.txt').decode().strip().split()[0]
    assert hashlib.sha256(package.read('RemoteConsentAgent-unsigned.exe')).hexdigest() == expected
    inventory = json.loads(package.read('THIRD-PARTY-LICENSES/inventory.json'))
    assert len(inventory) >= 12
    for dependency in ('cryptography', 'pillow', 'pywin32', 'pyinstaller'):
        entries = [name for name in names if name.lower().startswith('third-party-licenses/' + dependency + '/')]
        assert any('license' in name.rsplit('/', 1)[-1].lower() or 'copying' in name.rsplit('/', 1)[-1].lower() for name in entries), dependency
    assert any(name.endswith('runtime/LICENSE.txt') for name in names), 'Python runtime license missing'
    assert len([name for name in names if name.startswith('THIRD-PARTY-LICENSES/')]) > 10
    print('PASS: actual ZIP executable hash, dependency inventory and upstream licenses verified')
