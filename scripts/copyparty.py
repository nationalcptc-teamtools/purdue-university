#!/usr/bin/env python3
import os
from pathlib import Path
import secrets
import sys

ROOT = Path(__file__).resolve().parents[1]
base = Path(os.environ.get('TEAMTOOLS_HOME', '~/.local/share/teamtools')).expanduser().resolve()
if base == ROOT or ROOT in base.parents:
    sys.exit('CopyParty state must be outside the repository')
os.umask(0o077)
directory = base / 'copyparty'
directory.mkdir(parents=True, exist_ok=True)
for name in ('history', 'media'):
    (directory / name).mkdir(exist_ok=True)
config = directory / 'config.conf'
if not config.exists():
    password = secrets.token_urlsafe(24)
    with config.open('x') as stream:
        stream.write((ROOT / 'CopyParty' / 'copyparty.conf').read_text().replace('@PASSWORD@', password))
    with (directory / 'credentials').open('x') as stream:
        stream.write('admin:' + password + '\n')
print(directory / 'credentials')
