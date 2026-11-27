"""Rule packs: one engine, several product families.

    LVX_PACKS=vmware,vates   (default)  both families, auto-detected per file
    LVX_PACKS=vates                     Vates-only build (XCP-ng / Xen Orchestra), same behaviour as the old loglens-vates
    LVX_PACKS=vmware                    VMware-only build
"""
import os

ALL = ('vmware', 'vates')
ENABLED = tuple(p for p in (x.strip().lower() for x in os.environ.get('LVX_PACKS', 'vmware,vates').split(',')) if p in ALL) or ALL
VATES_PRODUCTS = ('xcpng', 'xo', 'vates')


def enabled(pack):
    return pack in ENABLED


def group(product):
    """'vates' for XCP-ng / Xen Orchestra products, 'vmware' for everything else."""
    return 'vates' if product in VATES_PRODUCTS else 'vmware'


def rule_pack(rule_id):
    return 'vates' if rule_id.startswith('xcp.') else 'vmware'


def vendor(rule_id=None, products=()):
    """Which vendor's documentation a finding belongs to: 'vates' or 'broadcom'."""
    if rule_id:
        return 'vates' if rule_pack(rule_id) == 'vates' else 'broadcom'
    products = [p for p in products if p and p != 'unknown']
    return 'vates' if products and all(group(p) == 'vates' for p in products) else 'broadcom'
