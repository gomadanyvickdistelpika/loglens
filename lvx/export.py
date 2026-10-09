"""Render an analysis result as Markdown / HTML / JSON."""
import html
import json


def to_json(res):
    return json.dumps(res, indent=2, default=str)


def to_markdown(res):
    w = res['window']
    L = ['# Log analysis report', '',
         '- **Bundle:** %s  (%s)' % (res['bundle'], ', '.join(res['products'])),
         '- **Customer issue:** %s' % (res['issue'] or '_not provided_'),
         '- **Incident time:** %s (%s)' % (w['anchor'], w['anchor_source']),
         '- **Analysis window:** %s -> %s  (-%sh / +%sh)' % (w['start'], w['end'], w['before_h'], w['after_h']),
         '']
    st = res['stats']
    L += ['**Noise removed:** scanned %s lines in %s files; %s were inside the window, %s outside it '
          '(%s error-level lines ignored as out-of-window).' % (
              st.get('lines_total', 0), st.get('files_scanned', 0), st.get('lines_in_window', 0),
              st.get('lines_outside_window', 0), st.get('errors_outside_window', 0)), '']
    L.append('## Ranked findings')
    if not res['findings']:
        L.append('_No significant findings inside the window. Widen the window or check the incident time._')
    for i, f in enumerate(res['findings'], 1):
        kb = ' · KB %s' % f['kb'] if f.get('kb') else ''
        L += ['', '### %d. %s  `score %s · %s · %s`%s' % (i, f['title'], f['score'], f['confidence'], f['severity'], kb),
              '- %s occurrences, first %s, last %s' % (f['count'], f['first_seen'], f['last_seen'])]
        if f.get('root_of'):
            L.append('- _Earlier warning that likely explains:_ %s' % f['root_of'])
        if f.get('symptom_of'):
            L.append('- _Likely a downstream symptom of:_ %s' % f['symptom_of'])
        if f.get('advice'):
            L.append('- **Next step:** %s' % f['advice'])
        if f.get('search'):
            L.append('- KB search phrase: `%s`' % f['search'])
        for s in f['samples'][:3]:
            L += ['', '  `%s:%s`' % (s['file'], s['line']), '  ```', '  ' + s['text'], '  ```']
    if res.get('sequence'):
        L += ['', '## Event sequence (first seen)']
        for s in res['sequence']:
            L.append('- %s - %s' % (s['time'], s['title']))
    if res.get('report_findings'):
        L += ['', '## GSS Toolbox / TDLog findings']
        for rf in res['report_findings']:
            L.append('- [%s] %s%s - score %s%s' % (rf['source'], rf['title'], ' (KB %s)' % rf['kb'] if rf.get('kb') else '',
                                                   rf['score'], ' **stale - outside window**' if rf.get('stale') else ''))
    return '\n'.join(L) + '\n'


def to_html(res):
    e = html.escape
    w = res['window']
    parts = ['<!doctype html><meta charset="utf-8"><title>Log analysis report</title>'
             '<style>body{font:14px/1.5 system-ui,sans-serif;max-width:980px;margin:24px auto;padding:0 16px;color:#1b1f24}'
             'h1{font-size:22px}.f{border:1px solid #d0d7de;border-radius:8px;padding:12px 14px;margin:12px 0}'
             '.b{display:inline-block;padding:1px 8px;border-radius:10px;background:#eaeef2;font-size:12px;margin-left:6px}'
             'pre{background:#f6f8fa;padding:8px;overflow:auto;border-radius:6px;font-size:12px}'
             '.crit{border-left:4px solid #cf222e}.high{border-left:4px solid #bc4c00}.medium{border-left:4px solid #9a6700}.low{border-left:4px solid #6e7781}'
             '.stale{opacity:.6}</style>']
    parts.append('<h1>Log analysis report</h1>')
    parts.append('<p><b>Bundle:</b> %s (%s)<br><b>Issue:</b> %s<br><b>Incident time:</b> %s (%s)<br><b>Window:</b> %s &rarr; %s</p>' % (
        e(res['bundle']), e(', '.join(res['products'])), e(res['issue'] or 'not provided'), e(str(w['anchor'])),
        e(w['anchor_source']), e(str(w['start'])), e(str(w['end']))))
    st = res['stats']
    parts.append('<p><b>Noise removed:</b> %s lines scanned, %s in window, %s outside; %s out-of-window error lines ignored.</p>' % (
        st.get('lines_total', 0), st.get('lines_in_window', 0), st.get('lines_outside_window', 0), st.get('errors_outside_window', 0)))
    for i, f in enumerate(res['findings'], 1):
        cls = {'critical': 'crit', 'error': 'high'}.get(f['severity'], f['severity'])
        parts.append('<div class="f %s"><b>%d. %s</b><span class="b">score %s</span><span class="b">%s</span>%s'
                     % (e(cls), i, e(f['title']), f['score'], e(f['confidence']),
                        '<span class="b">KB %s</span>' % e(str(f['kb'])) if f.get('kb') else ''))
        parts.append('<br>%s occurrences &middot; first %s &middot; last %s' % (f['count'], e(str(f['first_seen'])), e(str(f['last_seen']))))
        if f.get('root_of'):
            parts.append('<br><i>Earlier warning that likely explains: %s</i>' % e(f['root_of']))
        if f.get('symptom_of'):
            parts.append('<br><i>Likely a downstream symptom of: %s</i>' % e(f['symptom_of']))
        if f.get('advice'):
            parts.append('<br><b>Next step:</b> %s' % e(f['advice']))
        for s in f['samples'][:3]:
            parts.append('<pre>%s:%s\n%s</pre>' % (e(s['file']), s['line'], e(s['text'])))
        parts.append('</div>')
    for rf in res.get('report_findings', []):
        parts.append('<div class="f %s"><b>[%s] %s</b>%s</div>' % ('stale' if rf.get('stale') else '', e(rf['source']), e(rf['title']),
                                                                     ' (stale, outside window)' if rf.get('stale') else ''))
    return ''.join(parts)
