"""Personal data — the class the infrastructure detector does not have.

The detection service runs a CYBER security NER: its labels are `MALWARE`,
`THREAT_ACTOR`, `CVE_ID`, `LOCATION`, `ORGANIZATION`. There is no `PERSON`
among them, so no person was ever detected — not a customer, not the on-call
engineer, in any language. And nothing counted it: a value nobody detects
produces no vault entry, no unresolved surrogate and no `public_by_shape` line.

This package adds the missing class from OUR side of the D7 boundary. The model
is Apache-2.0, so it does not belong on the GPL side; and the AnonShield
virtualenv is pinned and fragile, so it does not go there either.
"""
