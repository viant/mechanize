#!/usr/bin/env python3
"""Package explicit application skill mappings and their public Markdown guides."""
import json
from pathlib import Path
import re
import sys


def package(root, destination):
    mapping = json.loads((root / 'applications.json').read_text())
    if mapping.get('version') != 1:
        raise ValueError('unsupported application skill mapping version')
    skills = []
    seen = set()
    for entry in mapping['skills']:
        name = entry['id']
        if not re.fullmatch(r'mechanize-[a-z0-9-]+', name) or name in seen:
            raise ValueError('unique skill directory required')
        seen.add(name)
        directory = root / name
        if not (directory / 'SKILL.md').is_file():
            raise ValueError(f'missing entrypoint: {name}')
        if not entry['bundleIDs'] or any(not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]+', b) for b in entry['bundleIDs']):
            raise ValueError('explicit application bundle IDs required')
        documents = []
        paths = [directory / 'SKILL.md'] + sorted((directory / 'references').rglob('*.md'))
        for path in paths:
            if not path.resolve().is_relative_to(directory.resolve()):
                raise ValueError('skill document escapes its directory')
            content = path.read_text()
            if len(content.encode()) > 262144:
                raise ValueError('skill document exceeds size limit')
            if content.startswith('---\n'):
                content = content.split('\n---\n', 1)[1].lstrip()
            title = next((line[2:] for line in content.splitlines() if line.startswith('# ')), path.stem)
            documents.append({'path': str(path.relative_to(directory)), 'title': title, 'content': content})
        skills.append({**entry, 'documents': documents})
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps({'version': 1, 'skills': skills}, indent=2) + '\n')


if __name__ == '__main__':
    package(Path(__file__).resolve().parents[1] / 'skills', Path(sys.argv[1]))
