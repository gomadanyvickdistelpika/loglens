"""Open support bundles: folders, zip, tar/tgz (nested), single logs, gz files.

Archives are unpacked (safely, size-capped) into a per-bundle work directory so
every viewer/analysis operation works on plain files. The work dir is removed on close.
"""
import gzip
import os
import re
import shutil
import tarfile
import tempfile
import zipfile

SKIP_EXT = {'.dmp', '.core', '.zdump', '.vmdk', '.iso', '.vib', '.rpm', '.so', '.jar', '.class',
            '.vmem', '.vmsn', '.vmss', '.nvram', '.ova', '.ovf', '.exe', '.dll', '.pyc', '.bin',
            '.img', '.raw', '.dat'}
ARCHIVE_RE = re.compile(r'\.(zip|tar|tgz|tar\.gz|tar\.bz2|tbz2|tar\.xz)$', re.I)
MAX_FILE = 1 << 30            # 1 GiB per member
MAX_TOTAL = 24 << 30          # 24 GiB per bundle
MAX_DEPTH = 4
_BAD = re.compile(r'[<>:"|?*\x00-\x1f]')


class BundleError(Exception):
    pass


def _safe_rel(name):
    parts = []
    for p in name.replace('\\', '/').split('/'):
        if p in ('', '.'):
            continue
        if p == '..':
            return None
        parts.append(_BAD.sub('_', p)[:120])
    return os.path.join(*parts) if parts else None


class _Budget:
    def __init__(self):
        self.total = 0

    def add(self, n):
        self.total += n
        if self.total > MAX_TOTAL:
            raise BundleError("Bundle exceeds the %d GiB extraction cap" % (MAX_TOTAL >> 30))


def _copy_stream(src, dst_path, budget):
    os.makedirs(os.path.dirname(dst_path), exist_ok=True)
    n = 0
    with open(dst_path, 'wb') as out:
        while True:
            b = src.read(1 << 20)
            if not b:
                break
            n += len(b)
            if n > MAX_FILE:
                break
            out.write(b)
    budget.add(n)


def _wanted(name, size):
    ext = os.path.splitext(name.lower())[1]
    if ext in SKIP_EXT:
        return False
    return size <= MAX_FILE


def _extract(src_path, dest, budget, depth=0):
    if depth > MAX_DEPTH:
        return
    low = src_path.lower()
    os.makedirs(dest, exist_ok=True)
    if low.endswith('.zip') or zipfile.is_zipfile(src_path):
        with zipfile.ZipFile(src_path) as zf:
            for zi in zf.infolist():
                if zi.is_dir():
                    continue
                rel = _safe_rel(zi.filename)
                if not rel or not _wanted(zi.filename, zi.file_size):
                    continue
                target = os.path.join(dest, rel)
                with zf.open(zi) as f:
                    _handle_member(f, target, rel, budget, depth)
        return
    try:
        tf = tarfile.open(src_path, 'r:*')
    except tarfile.TarError as e:
        raise BundleError("Cannot read archive %s: %s" % (os.path.basename(src_path), e))
    with tf:
        for ti in tf:
            if not ti.isfile():
                continue
            rel = _safe_rel(ti.name)
            if not rel or not _wanted(ti.name, ti.size):
                continue
            target = os.path.join(dest, rel)
            f = tf.extractfile(ti)
            if f is None:
                continue
            with f:
                _handle_member(f, target, rel, budget, depth)


def _handle_member(f, target, rel, budget, depth):
    if ARCHIVE_RE.search(rel):
        # nested archive: stage then unpack beside it
        tmp = target + '.__stage'
        _copy_stream(f, tmp, budget)
        try:
            _extract(tmp, target + '_extracted', budget, depth + 1)
        except (BundleError, tarfile.TarError, zipfile.BadZipFile, EOFError, OSError):
            shutil.move(tmp, target)   # keep as opaque file if it will not unpack
        else:
            os.remove(tmp)
    else:
        _copy_stream(f, target, budget)


class Bundle:
    def __init__(self, bundle_id, source, root, workdir, display):
        self.id = bundle_id
        self.source = source
        self.root = root          # directory (or single file's parent) holding the data
        self.workdir = workdir    # temp dir to delete on close (or None)
        self.display = display
        self.single_file = None

    def close(self):
        if self.workdir and os.path.isdir(self.workdir):
            shutil.rmtree(self.workdir, ignore_errors=True)

    def resolve(self, rel):
        p = os.path.realpath(os.path.join(self.root, rel))
        if not (p == os.path.realpath(self.root) or p.startswith(os.path.realpath(self.root) + os.sep)):
            raise BundleError("Path escapes bundle")
        return p

    def list_files(self):
        out = []
        for dp, _dn, fns in os.walk(self.root):
            for fn in fns:
                full = os.path.join(dp, fn)
                try:
                    sz = os.path.getsize(full)
                except OSError:
                    continue
                out.append({'path': os.path.relpath(full, self.root).replace(os.sep, '/'), 'size': sz})
        out.sort(key=lambda e: e['path'])
        return out


def open_bundle(bundle_id, path, work_base=None):
    path = os.path.abspath(path)
    if not os.path.exists(path):
        raise BundleError("Not found: %s" % path)
    if os.path.isdir(path):
        return Bundle(bundle_id, path, path, None, os.path.basename(path.rstrip('/\\')) or path)
    name = os.path.basename(path)
    if ARCHIVE_RE.search(name) or zipfile.is_zipfile(path) or _is_tar(path):
        wd = tempfile.mkdtemp(prefix='lvx_', dir=work_base)
        root = os.path.join(wd, 'bundle')
        try:
            _extract(path, root, _Budget())
        except Exception:
            shutil.rmtree(wd, ignore_errors=True)
            raise
        return Bundle(bundle_id, path, root, wd, name)
    # single file: expose in its own directory view
    wd = tempfile.mkdtemp(prefix='lvx_', dir=work_base)
    root = os.path.join(wd, 'bundle')
    os.makedirs(root)
    shutil.copy2(path, os.path.join(root, name))
    b = Bundle(bundle_id, path, root, wd, name)
    b.single_file = name
    return b


def _is_tar(path):
    try:
        return tarfile.is_tarfile(path)
    except OSError:
        return False


def open_text(path):
    """Iterate decoded lines of a text or .gz file (never raises on bad bytes)."""
    if path.lower().endswith('.gz'):
        f = gzip.open(path, 'rt', encoding='utf-8', errors='replace', newline='')
    else:
        f = open(path, 'rt', encoding='utf-8', errors='replace', newline='')
    with f:
        for line in f:
            yield line.rstrip('\r\n')


def looks_binary(path):
    try:
        op = gzip.open if path.lower().endswith('.gz') else open
        with op(path, 'rb') as f:
            return b'\x00' in f.read(4096)
    except (OSError, EOFError, gzip.BadGzipFile):
        return True
