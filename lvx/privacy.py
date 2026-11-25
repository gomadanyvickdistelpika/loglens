"""Deterministic redaction for reports that leave the machine (ticket attachments, customer updates).

Ported from the vmware-case-agent project and hardened for LOG text: the original phone-number pattern also matched
timestamps and IP addresses, which would destroy the evidence, so phone numbers now need a '+' country code or brackets.
Official documentation links (Broadcom, VMware, Vates, XCP-ng) are kept so KB references still work."""
import re

KEEP_LINK_HOSTS = ('knowledge.broadcom.com', 'docs.vmware.com', 'techdocs.broadcom.com', 'kb.vmware.com', 'xcp-ng.org',
                   'docs.xcp-ng.org', 'xen-orchestra.com', 'docs.xen-orchestra.com', 'vates.tech', 'github.com/vatesfr')

_LINK = re.compile(r'https?://[^\s<>"\')\]]+', re.I)
_IPV4 = re.compile(r'(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])')

RULES = (
    ('private_key', re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----', re.S), '[REDACTED_PRIVATE_KEY]'),
    ('secret', re.compile(r'(?i)\b(password|passwd|pwd|passcode|secret|api[_-]?key|token)\b(\s*[:=]\s*)(?!\[REDACTED)[^\s,;"\']+'), r'\1\2[REDACTED_SECRET]'),
    ('bearer', re.compile(r'(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}'), 'Bearer [REDACTED_SECRET]'),
    ('email', re.compile(r'\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b', re.I), '[REDACTED_EMAIL]'),
    ('phone', re.compile(r'(?<![\w.:/-])\+\d{1,3}[ .-]?(?:\(\d{1,4}\)|\d{1,4})[ .-]?\d{3,4}[ .-]?\d{3,4}(?![\w])'), '[REDACTED_PHONE]'),
    ('case_id', re.compile(r'\b(?:case|sr|ticket)\s*(?:id|#|number|no\.?|:)?\s*[-:]?\s*(?=[A-Z0-9-]*\d)[A-Z0-9][A-Z0-9-]{5,}\b', re.I), '[REDACTED_CASE_ID]'),
    ('person_name', re.compile(r'(?im)\b(customer|contact|name)\s*[:=]\s*[A-Z][A-Za-z\'-]+(?:\s+[A-Z][A-Za-z\'-]+){1,3}'), r'\1: [REDACTED_NAME]'),
)


def _link_sub(m):
    url = m.group(0)
    host = re.sub(r'^https?://', '', url, flags=re.I).lower()
    return url if any(host.startswith(h) or ('.' + h) in host.split('/')[0] for h in KEEP_LINK_HOSTS) else '[REDACTED_LINK]'


def redact(text, mask_ips=True, extra_terms=()):
    """Return (clean_text, categories). `extra_terms` = literal names to mask (customer, hostnames, VM names)."""
    cleaned = (text or '').replace('\x00', '')
    found = []
    for cat, rx, rep in RULES:
        cleaned, n = rx.subn(rep, cleaned)
        if n:
            found.append(cat)
    cleaned, n = _LINK.subn(_link_sub, cleaned)
    if n and '[REDACTED_LINK]' in cleaned:
        found.append('link')
    if mask_ips:
        cleaned, n = _IPV4.subn('[REDACTED_IP]', cleaned)
        if n:
            found.append('ipv4')
    for i, term in enumerate(t for t in extra_terms if t and len(t.strip()) >= 3):
        cleaned, n = re.subn(re.escape(term.strip()), '[REDACTED_%d]' % (i + 1), cleaned, flags=re.I)
        if n:
            found.append('custom_term')
    return cleaned, tuple(dict.fromkeys(found))
