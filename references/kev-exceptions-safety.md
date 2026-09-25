# KEV + exceptions safety reference

Scope: `src/dep_evidence/kev.py`, `src/dep_evidence/exceptions.py` and their
tests. This file records the safety rules the slice must satisfy. A review
cannot be completed against a contract that is not written down.

## KEV join

1. The join is exact and normalized only. No fuzzy, substring or vendor
   matching. A match means "this CVE appears in KEV", not "this Maven
   component was exploited".
2. `CVE-<4 digits>-<4..19 digits>` is the only accepted CVE form. `CVE-2026-1234`
   is valid. `CVE-2026-123` and `CVE-2026-12345-extra` are not. The
   CVE-shaped prefix is the literal `CVE-` after detection-only folding, so
   `CVEAT-2026-1234`, `CVE1-2026-1234` and a bare `CVE` are ordinary
   identifiers, not malformed CVE attempts.
3. A CVE-shaped but structurally invalid identifier, in the advisory `id` or in
   any alias, yields `review`. It must never yield `not_known_exploited`, and
   it must never produce a match.
4. An identifier that only *looks* like a CVE after Unicode folding also yields
   `review`. NFKC covers fullwidth, mathematical and modifier forms; cross-script
   homoglyphs in either ASCII case (Cyrillic `с`/`в`/`е` and `С`/`В`/`Е`, Greek
   `ε`/`Ε`) and Latin small capitals (`ᴄ`/`ᴠ`/`ᴇ`) require an explicit skeleton.
   Detection folding is `NFKC → strip → uppercase → skeleton translation`; doing
   the translation before uppercase leaves lowercase homoglyphs looking like
   ordinary IDs. Detection only — the identifier used for matching is never
   normalized this way.
5. Ordinary namespaces are not CVE-shaped and must stay clean: `GHSA-…`,
   `RUSTSEC-…`, `PYSEC-…`, `OSV-…`, `DSA-…`, `CWE-…`, `MSRC-…`, `DLA-…`,
   `USN-…`, `VEX-…`, `ALAS-…`. A substitution that changes the skeleton into a
   non-CVE string (for example `ВVE`) is an ordinary identifier, not a lookalike.
6. Every alias is validated before the join, so a valid alias cannot hide a
   malformed sibling, in either order.
7. The advisory `id` is validated on the same terms as an alias.
8. Snapshot and alias containers fail closed. A missing, non-iterable, empty or
   exploding input yields `review`; an exception raised while consuming either
   container must not escape `match_kev`. Each container is consumed exactly
   once — a list subclass or iterator that fails on a second pass must not
   crash the join.
8a. The advisory `aliases` field is optional in the official OSV schema and may
   also be an explicit JSON `null`. A missing key, `[]` and `null` are all
   valid and must never produce `review` on their own; a direct `CVE-…` advisory
   `id` with no aliases still joins normally.
9. A malformed entry inside an otherwise valid snapshot yields `review`.
10. Outer-whitespace and case normalization of a *valid* CVE is expected
    behaviour, not a defect.

## Exceptions

11. Identity matching normalizes outer whitespace only. Maven coordinates are
    case-sensitive, so `casefold()` is forbidden.
12. Every rule produces a visible decision: `active`, `expired` or
    `inapplicable`. A rule is never silently dropped.
13. An exception annotates a copy of the finding; the original is never mutated
    and nested evidence is deep-copied.
14. An exception never erases a finding or its status.
15. Prior `exceptions` data is never discarded. A list is preserved in order; an
    explicit non-list value — including JSON `null` — is kept as the first
    element so malformed producer data stays visible. Only a missing key means
    "no prior data".
16. `schema_version` is a strict JSON integer (`type(x) is int`, so `true` is
    rejected). `expires_on` is a real calendar date in `YYYY-MM-DD` form.

## Known deliberate non-defects

- Equal `introduced == last_affected` in OSV stays `review /
  ambiguous_event_ordering`. The OSV data-quality guide treats such a
  producer-record as incorrect, so the result must not claim `not_affected`.
- `1-1 > 1.0` is correct Apache `ComparableVersion` ordering. See
  `docs/superpowers/specs/2026-09-25-dep-evidence-design.md`.
