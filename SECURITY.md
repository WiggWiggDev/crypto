# Security Policy

## Reporting a vulnerability

Email **security@wiggwigg.ca** (in French, **securite@wiggwigg.ca**) with enough detail to
reproduce the issue. You will get an acknowledgement promptly.

We offer a good-faith safe harbor for responsible disclosure: if you make a sincere effort to
follow this policy, we will not pursue or support legal action against you for your research.
Please give us a reasonable window to investigate and fix before disclosing publicly.

## Scope

This repository holds the cryptographic primitives. Findings in the primitives themselves
(key derivation, encryption, sealing, signing, recovery) belong here. Findings in the
WIGGWIGG application or its services can go to the same address; just note that they are
application-level.

## A note on constants

The domain-separation strings and on-disk scheme versions in this code are load-bearing:
stored data depends on them. They change through the versioning mechanism in `versions.ts`,
never by editing a constant in place.
