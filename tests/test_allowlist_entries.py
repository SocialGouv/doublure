"""Public entries of `config/allowlist.txt`, pinned in BOTH directions.

Round 8 paid the lesson: the allowlist is the only rule in the whole loop that
makes values PUBLIC, therefore the only one whose failure mode is a SILENT
leak — no 400, no 503, no vault entry, no unresolved surrogate, nothing to
count. Everything else fails loudly. So every entry added here comes with its
counter-test, and the counter-test is written first.

These are EXACT entries, which round 9 defined as the safest kind: a decision
taken token by token, valid everywhere including inside a composite value. No
wildcard on `anthropic.com` — that is the `*.amazonaws.com` trap, where a
RESOURCE endpoint carries the account identifier. The endpoints are enumerated.
"""
from __future__ import annotations

import pytest

from anonproxy.allowlist import Allowlist


@pytest.fixture(scope="module")
def public():
    return Allowlist.load()


# --------------------------------------------------------------------------- #
# What must be public — otherwise the model loses a reference it needs
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("value", [
    # Anthropic, enumerated
    "claude.ai", "claude.com", "anthropic.com",
    "api.anthropic.com", "console.anthropic.com",
    # RFC 2606 — reserved for documentation, provably nobody's
    "example.com", "example.net", "example.org", "www.example.com",
    "user@example.com", "jane.doe@example.org",
    # public registry
    "iana.org", "www.iana.org",
    # product names shaped like a domain
    "node.js", "next.js",
])
def test_a_public_reference_stays_readable(value, public):
    assert public(value), f"{value!r} would be substituted"


# --------------------------------------------------------------------------- #
# What must NOT become public — the counter-test of every entry above
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("value", [
    # a subdomain under the operator's own zone, whatever it is called
    "claude.ai.acme.internal",
    "anthropic.com.acme.corp",
    "example.com.acme.internal",
    # the wildcard trap: a RESOURCE endpoint carries an identifier
    "tenant-acme-nda.anthropic.com",
    "db-prod.example.com",
    "secret-project.iana.org",
    # a real person at a reserved domain is still a real person
    "alice.dupont.dgfip@example.com",
    "prenom.nom@acme.corp",
    # the product name is exact, its neighbours are not
    "node.js.acme.internal",
    "billing.node.js",
])
def test_a_neighbouring_identifier_is_not_public(value, public):
    assert not public(value), (
        f"{value!r} made public: it would leave in the clear, with no trace")


def test_the_reserved_tlds_are_not_open(public):
    """RFC 2606 also reserves `.test`, `.invalid`, `.example` and `.localhost`.
    They are nobody's on the public Internet — which does not stop an operator
    from using one as an INTERNAL convention. `domaines_fictifs=reserves` draws
    surrogates there; opening the TLD would make a real host under it public."""
    for value in ("db-01.test", "vault.invalid", "srv.example", "api.localhost"):
        assert not public(value), f"{value!r} made public by its TLD alone"
