"""
Cross-walk from a mandate onto OAuth 2.0 Rich Authorization Requests
(RFC 9396) ``authorization_details``. Banks already express fine-grained
consent this way (open banking payment-initiation and account-access consents
ride on it), so a mandate that can be read as an authorization detail is one a
bank's existing consent stack can reason about.

One mandate becomes one authorization detail. The RFC's common fields carry
what they can: ``actions`` from the mandate's action allow-list, ``locations``
from the merchant allow-list or, for a per-verb scoped mandate, the sorted
counterparty ids, ``datatypes`` from the categories, ``identifier`` from the
mandate id. Everything with no common-field home (amount cap, approval rules,
denied merchants, the per-verb counterparty map, usage limits, the revocation
list id, the parent of a delegated mandate, the intent sentence) travels as
type-specific fields, which the RFC permits. ``valid_from`` is ``not_before``
when the mandate has one, else ``issued_at``. The mapping is a draft; the
``type`` is MandateKit's own until a registry assigns one.
"""

import copy
from typing import Dict, List

AUTHORIZATION_DETAIL_TYPE = "mandatekit:mandate:v0.2"


def to_authorization_details(mandate: Dict) -> List[Dict]:
    c = mandate.get("constraints") or {}
    d: Dict = {
        "type": AUTHORIZATION_DETAIL_TYPE,
        "identifier": mandate["mandate_id"],
        "subject": {"agent_id": mandate["subject"]["agent_id"]},
        "valid_from": c["not_before"] if isinstance(c.get("not_before"), str) else mandate["issued_at"],
        "valid_until": mandate["expires_at"],
    }
    if isinstance(mandate["subject"].get("public_key"), str):
        d["subject"]["public_key"] = mandate["subject"]["public_key"]
    if "actions" in c:
        d["actions"] = list(c["actions"])
    merchants = c.get("merchants") or {}
    if "allow" in merchants:
        d["locations"] = list(merchants["allow"])
    elif isinstance(c.get("counterparties"), dict):
        d["locations"] = sorted(c["counterparties"])
    if "deny" in merchants:
        d["denied_locations"] = list(merchants["deny"])
    if "categories" in c:
        d["datatypes"] = list(c["categories"])
    if c.get("intent"):
        d["intent"] = c["intent"]
    if c.get("max_amount"):
        d["max_amount"] = copy.deepcopy(c["max_amount"])
    if c.get("approval"):
        d["approval"] = copy.deepcopy(c["approval"])
    if isinstance(c.get("counterparties"), dict):
        d["counterparties"] = copy.deepcopy(c["counterparties"])
    if isinstance(c.get("limits"), dict):
        d["limits"] = copy.deepcopy(c["limits"])
    if isinstance(c.get("revocation"), dict):
        d["revocation"] = copy.deepcopy(c["revocation"])
    delegation = c.get("delegation")
    if isinstance(delegation, dict):
        out: Dict = {}
        parent = delegation.get("parent")
        parent_mandate = parent.get("mandate") if isinstance(parent, dict) else None
        if isinstance(parent_mandate, dict) and "mandate_id" in parent_mandate:
            out["parent"] = parent_mandate["mandate_id"]
        if "max_depth" in delegation:
            out["max_depth"] = delegation["max_depth"]
        if out:
            d["delegation"] = out
    return [d]
