#!/usr/bin/env python3
"""Keep the Vates-default distribution (the `loglens-vates` repo) in step with this repo, the single source of truth.

    python tools/sync_variants.py ../loglens-vates

Copies lvx/, tests/, tools/, docs/ and examples/virtual-estate/ (replacing the target's copies) and changes exactly one thing:
the default rule pack in lvx/packs.py becomes `vates`, so `python -m lvx serve` there analyses XCP-ng / Xen Orchestra out of the box
(set LVX_PACKS=vmware,vates to get both).  Root files (README, Dockerfile, launcher, run scripts, the target's own examples/) are left alone.
Run the target's tests with LVX_PACKS=vmware,vates: the shared test-suite also covers the VMware pack."""
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.abspath(os.path.join(HERE, '..'))
COPY = ['lvx', 'tests', 'tools', 'docs', os.path.join('examples', 'virtual-estate')]
IGNORE = shutil.ignore_patterns('__pycache__', '*.pyc', '.pytest_cache')


def main(argv):
    if len(argv) < 2:
        sys.exit(__doc__)
    dst = os.path.abspath(argv[1])
    if not os.path.isdir(os.path.join(dst, '.git')):
        sys.exit('%s is not a git checkout' % dst)
    for rel in COPY:
        s, d = os.path.join(SRC, rel), os.path.join(dst, rel)
        if not os.path.isdir(s):
            continue
        if os.path.isdir(d):
            shutil.rmtree(d)
        os.makedirs(os.path.dirname(d), exist_ok=True)
        shutil.copytree(s, d, ignore=IGNORE)
        print('synced', rel)
    p = os.path.join(dst, 'lvx', 'packs.py')
    with open(p, encoding='utf-8') as f:
        text = f.read()
    old = "os.environ.get('LVX_PACKS', 'vmware,vates')"
    if old not in text:
        sys.exit('packs.py: default marker not found')
    with open(p, 'w', encoding='utf-8', newline='\n') as f:
        f.write(text.replace(old, "os.environ.get('LVX_PACKS', 'vates')").replace('LVX_PACKS=vmware,vates   (default)', 'LVX_PACKS=vmware,vates'))
    print('default pack in %s is now vates' % os.path.relpath(p, dst))


if __name__ == '__main__':
    main(sys.argv)
