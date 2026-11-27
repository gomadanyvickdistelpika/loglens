"""KB research attached to every finding: Broadcom KB for VMware findings, public Vates / XCP-ng / Xen Orchestra pages for Vates findings.

Data comes from lvx/kb_library.json (Broadcom) and lvx/kb_library_vates.json (Vates): dated SNAPSHOTS of web-search results
(title + URL, and the cause/resolution the search-result SUMMARIES stated; article text was not read unless an entry's note says so),
plus optional extra entries from the file named by LVX_KB_FILE.  This is NOT a live lookup.  When nothing matches, the result says so
instead of guessing."""
import json
import os
import re

from . import packs

_DIR = os.path.dirname(os.path.abspath(__file__))
_FILES = {'broadcom': 'kb_library.json', 'vates': 'kb_library_vates.json'}
VENDOR_LABEL = {'broadcom': 'Broadcom', 'vates': 'Vates/XCP-ng'}
MAX_SHOWN = 4
_cache = None

_HOSTS = {'github.com': 'GitHub', 'xen-orchestra.com': 'Xen Orchestra', 'docs.xen-orchestra.com': 'Xen Orchestra docs',
          'docs.xcp-ng.org': 'XCP-ng docs', 'xcp-ng.org': 'XCP-ng forum/blog'}


def article_url(aid):
    aid = str(aid)
    if aid.startswith('https://'):
        return aid                                  # Vates entries carry full URLs
    if aid.startswith('legacy:'):
        return 'https://knowledge.broadcom.com/external/article?legacyId=' + aid[7:]
    return 'https://knowledge.broadcom.com/external/article/' + aid


def _art(a):
    """Article dict for output: id, title, url, a site label and the date it was seen (Vates)."""
    url = article_url(a['id'])
    if url.startswith('https://knowledge.broadcom.com'):
        return dict(id=a['id'].replace('legacy:', 'legacy '), title=a['title'], url=url, label='KB ' + a['id'].replace('legacy:', 'legacy '), seen=a.get('seen', ''))
    host = url.split('/')[2]
    label = _HOSTS.get(host, host)
    if host == 'xcp-ng.org' and '/forum/' not in url:
        label = 'XCP-ng site'
    return dict(id=url, title=a['title'], url=url, label=label, seen=a.get('seen', ''))


def _vendor_of_entry(e):
    return 'vates' if any(r.startswith('xcp.') for r in e.get('rules', [])) else 'broadcom'


def _read(path):
    with open(path, encoding='utf-8') as f:
        return json.load(f)


def _load():
    """Combined view: {'researched', 'source', 'entries' (all enabled vendors), 'libs': {vendor: library}}."""
    global _cache
    if _cache is not None:
        return _cache
    libs = {}
    for v, fn in _FILES.items():
        if packs.enabled('vates' if v == 'vates' else 'vmware'):
            libs[v] = _read(os.path.join(_DIR, fn))
    extra = os.environ.get('LVX_KB_FILE')
    if extra and os.path.isfile(extra):
        try:
            for e in _read(extra).get('entries', []):
                v = _vendor_of_entry(e)
                if v in libs:
                    libs[v]['entries'] = libs[v]['entries'] + [e]
        except (OSError, ValueError):
            pass                      # a broken user file must never break an analysis
    entries = []
    for v, lib in libs.items():
        for e in lib['entries']:
            e['_rx'] = re.compile(e['match'], re.I) if e.get('match') else None
            e['_vendor'] = v
            entries.append(e)
    first = libs[next(iter(libs))]
    _cache = dict(researched=first['researched'], source=first['source'], entries=entries, libs=libs)
    return _cache


def reset_cache():
    global _cache
    _cache = None


def library_info(vendor='broadcom'):
    lib = _load()
    one = lib['libs'].get(vendor) or lib['libs'][next(iter(lib['libs']))]
    return dict(researched=one['researched'], source=one['source'], entries=len(one['entries']), vendor=VENDOR_LABEL.get(vendor, vendor))


def _entry_out(e, precision):
    return dict(topic=e['topic'], precision=precision, cause=e.get('cause', ''), resolution=e.get('resolution', []),
                notes=e.get('notes', ''), basis=e.get('basis', 'summary'), articles=[_art(a) for a in e['articles']])


def _template_entries(rule_id, text):
    """Entries from anonymised resolved-case templates / synthetic scenarios whose expected rule matches this finding."""
    if not rule_id:
        return []
    from . import templates
    out = []
    for t in templates.all_templates():
        if rule_id not in t['expect_rules']:
            continue
        if t.get('match') and not re.search(t['match'], text or '', re.I):
            continue
        synth = 'SYNTHETIC SCENARIO' in (t.get('notes') or '')
        out.append(dict(topic='%s %s: %s' % ('Scenario template' if synth else 'Resolved-case template', t['id'], t['title']), precision='case-template', synthetic=synth,
                        cause=t.get('cause', ''), resolution=t.get('resolution', []), notes=t.get('notes', ''), basis='case',
                        articles=[_art(k) for k in t.get('kb', []) if k.get('role') != 'noise'],
                        template=t['id'], evidence=t.get('evidence', '')))
    return out


def research(rule_id, text, search_phrase=None, report_kb=None, kind='rule', vendor=None):
    """Return {'status': 'found'|'none', 'entries': [...], 'more': n, 'searched': phrase, 'message': str, 'vendor': label}."""
    vendor = packs.vendor(rule_id) if rule_id else (vendor or 'broadcom')
    lib = _load()
    one = lib['libs'].get(vendor) or lib['libs'][next(iter(lib['libs']))]
    label = VENDOR_LABEL[vendor]
    base = dict(library_date=one['researched'], searched=search_phrase or '', vendor=label)
    if kind == 'report':
        kbs = [k for k in re.findall(r'\d{3,}', str(report_kb or ''))]
        if kbs:
            ents = [dict(topic='KB referenced by the GSS Toolbox/TDLog report', precision='report', cause='', resolution=[], notes='Resolution is in the article itself.', basis='report',
                         articles=[_art(dict(id=k, title='Broadcom KB %s' % k)) for k in kbs])]
            return dict(base, vendor='Broadcom', status='found', entries=ents, more=0, message='KB number(s) taken from the supplied report.')
        return dict(base, vendor='Broadcom', status='none', entries=[], more=0, message='No Broadcom KB is referenced by the report for this item.')
    if kind == 'generic' or not rule_id:
        return dict(base, status='none', entries=[], more=0,
                    message='No %s KB found: this message matches no known signature, so it was not researched. Use the search phrase manually.' % ('public Vates' if vendor == 'vates' else 'Broadcom'))
    tmpl = _template_entries(rule_id, text)
    hit, general = [], []                     # (priority, entry) - higher priority first, library order otherwise
    for e in lib['entries']:
        if rule_id not in e['rules']:
            continue
        if e['_rx'] is None:
            general.append((e.get('priority', 0), _entry_out(e, 'general')))
        elif e['_rx'].search(text or ''):
            hit.append((e.get('priority', 0), _entry_out(e, 'match')))
    ents = tmpl + [x for _p, x in sorted(hit, key=lambda t: -t[0])] + [x for _p, x in sorted(general, key=lambda t: -t[0])]
    if not ents:
        if vendor == 'vates':
            msg = ('No public Vates KB found in the LogLens KB library for this finding (researched %s; search summaries only, no article text read). '
                   'Try the search phrase manually on docs.xcp-ng.org, docs.xen-orchestra.com and the XCP-ng forum.' % one['researched'])
        else:
            msg = 'No Broadcom KB found in the LogLens KB library for this finding (researched %s).' % one['researched']
        return dict(base, status='none', entries=[], more=0, message=msg)
    if vendor == 'vates':
        msg = ('Matched from the LogLens KB library%s (public pages seen %s in web-search results, not a live search). '
               "Search-result summaries only; the article text was not read, except where an entry's note says the page itself was read."
               % (' and the synthetic scenarios' if tmpl else '', one['researched']))
    else:
        msg = ('Matched from the LogLens KB library and anonymised resolved-case templates (research snapshot %s, not a live search).' if tmpl else
               'Matched from the LogLens KB library (research snapshot %s, not a live search).') % one['researched']
    return dict(base, status='found', entries=ents[:MAX_SHOWN], more=max(0, len(ents) - MAX_SHOWN), message=msg)
