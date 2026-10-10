"""Broadcom KB research attached to every finding.

Data comes from lvx/kb_library.json: a dated SNAPSHOT of research on knowledge.broadcom.com (summaries of search results,
not article text) plus optional extra entries from the file named by LVX_KB_FILE.  This is NOT a live lookup.  When nothing
in the library matches a finding the result says so explicitly instead of guessing."""
import json
import os
import re

_LIB = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'kb_library.json')
MAX_SHOWN = 4
_cache = None


def article_url(aid):
    aid = str(aid)
    if aid.startswith('legacy:'):
        return 'https://knowledge.broadcom.com/external/article?legacyId=' + aid[7:]
    return 'https://knowledge.broadcom.com/external/article/' + aid


def _load():
    global _cache
    if _cache is not None:
        return _cache
    with open(_LIB, encoding='utf-8') as f:
        lib = json.load(f)
    extra = os.environ.get('LVX_KB_FILE')
    if extra and os.path.isfile(extra):
        try:
            with open(extra, encoding='utf-8') as f:
                lib['entries'] = lib['entries'] + json.load(f).get('entries', [])
        except (OSError, ValueError):
            pass                      # a broken user file must never break an analysis
    for e in lib['entries']:
        e['_rx'] = re.compile(e['match'], re.I) if e.get('match') else None
    _cache = lib
    return lib


def reset_cache():
    global _cache
    _cache = None


def library_info():
    lib = _load()
    return dict(researched=lib['researched'], source=lib['source'], entries=len(lib['entries']))


def _entry_out(e, precision):
    return dict(topic=e['topic'], precision=precision, cause=e.get('cause', ''), resolution=e.get('resolution', []),
                notes=e.get('notes', ''), basis=e.get('basis', 'summary'),
                articles=[dict(id=a['id'].replace('legacy:', 'legacy '), title=a['title'], url=article_url(a['id'])) for a in e['articles']])


def _template_entries(rule_id, text):
    """Entries from anonymised resolved-case templates whose expected rule matches this finding."""
    if not rule_id:
        return []
    from . import templates
    out = []
    for t in templates.all_templates():
        if rule_id not in t['expect_rules']:
            continue
        if t.get('match') and not re.search(t['match'], text or '', re.I):
            continue
        out.append(dict(topic='%s %s: %s' % ('Scenario template' if str(t.get('notes', '')).startswith('SYNTHETIC SCENARIO') else 'Resolved-case template', t['id'], t['title']), precision='case-template', synthetic=str(t.get('notes', '')).startswith('SYNTHETIC SCENARIO'), cause=t.get('cause', ''),
                        resolution=t.get('resolution', []), notes=t.get('notes', ''), basis='case',
                        articles=[dict(id=k['id'].replace('legacy:', 'legacy '), title=k['title'], url=article_url(k['id'])) for k in t.get('kb', []) if k.get('role') != 'noise'],
                        template=t['id'], evidence=t.get('evidence', '')))
    return out


def research(rule_id, text, search_phrase=None, report_kb=None, kind='rule'):
    """Return {'status': 'found'|'none', 'entries': [...], 'more': n, 'searched': phrase, 'message': str}."""
    lib = _load()
    base = dict(library_date=lib['researched'], searched=search_phrase or '')
    if kind == 'report':
        kbs = [k for k in re.findall(r'\d{3,}', str(report_kb or ''))]
        if kbs:
            ents = [dict(topic='KB referenced by the %s report' % ('GSS Toolbox/TDLog'), precision='report', cause='', resolution=[], notes='Resolution is in the article itself.', basis='report',
                         articles=[dict(id=k, title='Broadcom KB %s' % k, url=article_url(k)) for k in kbs])]
            return dict(base, status='found', entries=ents, more=0, message='KB number(s) taken from the supplied report.')
        return dict(base, status='none', entries=[], more=0, message='No Broadcom KB is referenced by the report for this item.')
    if kind == 'generic' or not rule_id:
        return dict(base, status='none', entries=[], more=0,
                    message='No Broadcom KB found: this message matches no known signature, so it was not researched. Use the search phrase manually.')
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
        return dict(base, status='none', entries=[], more=0,
                    message='No Broadcom KB found in the LogLens KB library for this finding (researched %s).' % lib['researched'])
    return dict(base, status='found', entries=ents[:MAX_SHOWN], more=max(0, len(ents) - MAX_SHOWN),
                message=('Matched from the LogLens KB library and anonymised resolved-case templates (research snapshot %s, not a live search).' if tmpl else
                         'Matched from the LogLens KB library (research snapshot %s, not a live search).') % lib['researched'])
