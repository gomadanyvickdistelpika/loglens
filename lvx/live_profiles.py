"""Saved SSH connection profiles (host, user, key path, product).  A password is NEVER stored or logged."""
import json
import os
import re
import uuid

from .live import LiveError, LiveSession, PRODUCTS, open_ssh, ssh_argv, validate_path, validate_target

PROFILE_FIELDS = ('name', 'host', 'port', 'user', 'key', 'product', 'host_key', 'extra_logs')


def _profile_file():
    base = os.environ.get('LVX_HOME') or os.path.join(os.path.expanduser('~'), '.lvx')
    return os.path.join(base, 'profiles.json')


def load_profiles():
    try:
        with open(_profile_file(), encoding='utf-8') as f:
            return [p for p in json.load(f) if isinstance(p, dict) and p.get('name')]
    except (OSError, ValueError):
        return []


def save_profile(p):
    clean = {k: p.get(k) for k in PROFILE_FIELDS}
    if not re.match(r'^[\w .@-]{1,60}$', clean['name'] or ''):
        raise LiveError('profile name: 1-60 letters, digits, space . _ @ -')
    validate_target(clean['host'], clean['user'], clean['port'])
    if clean['product'] not in PRODUCTS:
        raise LiveError('unknown product')
    clean['extra_logs'] = [validate_path(x) for x in (clean.get('extra_logs') or [])]
    clean['port'] = 22 if clean['port'] in (None, '') else int(clean['port'])
    clean['host_key'] = clean.get('host_key') or 'accept-new'
    profs = [x for x in load_profiles() if x['name'] != clean['name']] + [clean]
    path = _profile_file()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(profs, f, indent=1)
    return clean


def delete_profile(name):
    profs = [x for x in load_profiles() if x['name'] != name]
    path = _profile_file()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(profs, f, indent=1)


def start_ssh_session(spec, workdir, on_result=None, password=None, sid=None):
    """spec: host,user,port,key,product,host_key,extra_logs,interval,window_h,issue.  Returns a started LiveSession."""
    host, user, port = validate_target(spec.get('host'), spec.get('user'), spec.get('port'))
    product = spec.get('product')
    if product not in PRODUCTS:
        raise LiveError('unknown product %r (choose one of %s)' % (product, ', '.join(PRODUCTS)))
    key = (spec.get('key') or '').strip().strip('"') or None
    hk = spec.get('host_key') or 'accept-new'
    ssh_argv(host, user, port, key, hk, bool(password))       # validate everything up front, before any thread starts
    s = LiveSession(sid or uuid.uuid4().hex[:12], lambda: open_ssh(host, user, port, key, hk, password), product, workdir,
                    extra_logs=spec.get('extra_logs') or (), interval=float(spec.get('interval') or 10),
                    window_h=float(spec.get('window_h') or 2), issue=spec.get('issue') or '', on_result=on_result,
                    label='%s (%s@%s)' % (PRODUCTS[product]['label'], user or '-', host))
    return s.start()
