"""Retain upstream wheel metadata and runtime license texts in release packages."""
import importlib.metadata
import json
from pathlib import Path
import shutil
import sys

destination = Path(sys.argv[1])
destination.mkdir(parents=True, exist_ok=True)
inventory = []
for distribution in importlib.metadata.distributions():
    name = distribution.metadata['Name']
    target = destination / name
    target.mkdir(exist_ok=True)
    (target / 'METADATA.txt').write_text(str(distribution.metadata), encoding='utf-8')
    for file in distribution.files or []:
        if any(part.lower().startswith(('license', 'licence', 'copying', 'notice')) for part in file.parts):
            original = Path(distribution.locate_file(file))
            if original.is_file():
                relative = Path(*[part for part in file.parts if part not in ('..', '.')])
                output = target / relative
                output.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(original, output)
    inventory.append(dict(name=name, version=distribution.version))
base = Path(sys.base_prefix)
for path in [base / 'LICENSE.txt', base / 'tcl' / 'tcl8.6' / 'license.terms', base / 'tcl' / 'tk8.6' / 'license.terms']:
    if path.is_file():
        output = destination / 'runtime' / path.relative_to(base)
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, output)
(destination / 'inventory.json').write_text(json.dumps(inventory, indent=2), encoding='utf-8')
print('License inventory:', len(inventory), 'distributions')
