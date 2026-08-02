"""Phase 2 — résolution canonique (formes multiples → un enregistrement) et
table de priorité des recouvrements (§5 Phase 2, tâches 1 et 4).
Valeurs synthétiques uniquement."""
from __future__ import annotations

from anonproxy.surrogates.engine import SurrogateEngine
from anonproxy.surrogates.overlap import resolve_overlaps
from anonproxy.vault import Vault

MASTER = "b4" * 32
SCOPE = "project:demo"


def make_engine(tmp_path):
    return SurrogateEngine(vault=Vault(tmp_path / "v.db", master_key=MASTER), master_key=MASTER, scope_key=SCOPE)


# --------------------------- canonique ------------------------------------- #


def test_repo_formes_multiples_un_seul_enregistrement(tmp_path):
    eng = make_engine(tmp_path)
    url = eng.substitute_value("URL", "https://github.com/acme/payments-api")
    # forme courte org/nom rencontrée ensuite → dérivée du même enregistrement
    short = eng.substitute_value("REPO", "acme/payments-api")
    fake_org, fake_name = short.split("/")
    assert f"{fake_org}/{fake_name}" in url, f"formes divergentes : {url} vs {short}"
    # la forme SSH aussi
    ssh = eng.substitute_value("URL", "git@github.com:acme/payments-api.git")
    assert fake_org in ssh and fake_name in ssh


def test_hote_fqdn_puis_nom_court(tmp_path):
    eng = make_engine(tmp_path)
    fqdn = eng.substitute_value("HOSTNAME", "db-master-01.acme.internal")
    short = eng.substitute_value("HOSTNAME", "db-master-01")
    assert fqdn.startswith(short + "."), f"nom court incohérent : {fqdn} vs {short}"


def test_meme_org_prefixe_commun(tmp_path):
    eng = make_engine(tmp_path)
    a = eng.substitute_value("HOSTNAME", "api-1-prod.acme.internal")
    b = eng.substitute_value("HOSTNAME", "db-2-prod.acme.internal")
    assert a.split(".", 1)[1] == b.split(".", 1)[1], "zone d'org divergente (co-appartenance)"


# --------------------------- recouvrements --------------------------------- #


def span(t, s, e, txt, score=0.9):
    return {"type": t, "start": s, "end": e, "value": txt[s:e], "score": score}


def test_priorite_secret_sur_tout(tmp_path):
    txt = "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkZW1vIn0.c2lnbmF0dXJlZGVtbw"
    spans = [
        span("JWT", 6, len(txt), txt, 0.8),
        span("EMAIL_ADDRESS", 10, 20, txt, 0.99),
        span("HOSTNAME", 12, 30, txt, 0.99),
    ]
    kept = resolve_overlaps(spans)
    assert [s["type"] for s in kept] == ["JWT"]


def test_priorite_hostname_sur_ip_meme_span(tmp_path):
    txt = "10.1.2.3"
    spans = [span("IP_ADDRESS", 0, 8, txt, 0.85), span("HOSTNAME", 0, 8, txt, 0.6)]
    kept = resolve_overlaps(spans)
    assert [s["type"] for s in kept] == ["HOSTNAME"]


def test_chevauchement_partiel_deterministe(tmp_path):
    txt = "alice.demo@example.org"
    spans = [
        span("EMAIL_ADDRESS", 0, 22, txt, 1.0),
        span("HOSTNAME", 0, 10, txt, 0.6),   # 'alice.demo' — faux ami
        span("URL", 11, 22, txt, 0.5),
    ]
    kept = resolve_overlaps(spans)
    assert [s["type"] for s in kept] == ["EMAIL_ADDRESS"]


def test_spans_disjoints_tous_gardes(tmp_path):
    txt = "a@b.example puis 10.0.0.1"
    spans = [span("EMAIL_ADDRESS", 0, 11, txt, 1.0), span("IP_ADDRESS", 17, 25, txt, 0.85)]
    kept = resolve_overlaps(spans)
    assert len(kept) == 2


# --------------------------- transform ------------------------------------- #


def test_transform_splice_et_cache(tmp_path):
    eng = make_engine(tmp_path)
    txt = "conn de 10.1.2.3 vers db-01.acme.internal ok"
    spans = [span("IP_ADDRESS", 8, 16, txt, 0.85), span("HOSTNAME", 22, 41, txt, 0.6)]
    out1 = eng.transform(txt, spans)
    out2 = eng.transform(txt, spans)
    assert out1 == out2
    assert "10.1.2.3" not in out1 and "db-01.acme.internal" not in out1
    assert out1.startswith("conn de ") and out1.endswith(" ok")


def test_morphologie_preservee_generique(tmp_path):
    eng = make_engine(tmp_path)
    s = eng.substitute_value("SERVICE_ACCOUNT", "svc-payments-prod")
    # Ce qui doit tenir : le préfixe de compte de service, l'environnement, et
    # le fait que le cœur du nom a bien changé. Le nombre exact de segments,
    # lui, n'est pas un invariant : `svc-billing-gateway-prod` est une forme
    # aussi courante que `svc-billing-prod`.
    assert s.startswith("svc-") and s.endswith("-prod") and s != "svc-payments-prod"
    coeur = s[len("svc-"):-len("-prod")]
    assert coeur and "payments" not in coeur, f"cœur du nom non substitué : {s}"
