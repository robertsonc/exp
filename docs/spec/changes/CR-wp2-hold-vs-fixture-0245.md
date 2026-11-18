# CR-wp2-hold-vs-fixture-0245

**From:** WP-2 (collector)  **Affects:** WP-0 (test/fixtures/exm/README.md), 03-collector.md §5

**What:** test/fixtures/exm/README.md says the 1m50s dns_hb failure on 8.8.8.8 (02:45:02-02:46:52)
must not page. With the specified hold_down_s = 20, a 110 s continuous failure necessarily outlasts
the hold, so the engine pages "down DNS" at 02:45 and resolves at 02:48. EXM did not page because
its resolver rule needed both resolvers silent for DNS; the single-resolver failure was below the
DNS rule's threshold in EXM's tick replay only by 2-s sampling artefacts.

**Why it is not fixed in code:** shortening or special-casing the hold would weaken the hold rule.
The golden test asserts the nine expected pages from 02:55 onward; the CLI replay shows the extra page.

**Proposal:** WP-0 amends the fixture README to list the 02:45 DNS page as an expected extra
(or marks the sequence "from 03:00"), or the spec defines a minimum failing-window for the DNS line
above hold_down_s.

**Compatibility:** documentation only; no schema or API change.

## Addendum (evidence)

`reference/exm/test/unit.py:231` replays EXM's alert engine from `2026-10-27T02:55:00Z` to `04:28:00Z`, so the nine
pages in the fixture README were never produced for 02:45; the "stays under the hold-down" wording is the README's
inference. The collector reproduces exactly the nine pages over that window
(`exp-collector replay ... --from 2026-10-27T02:55:00Z --to 2026-10-27T04:28:00Z`, tested in
`collector/tests/golden/test_golden_cli_replay.py`). Requested WP-0 action: reword README lines 49-52 to
"over 02:55-04:28". No collector code change is needed or made.
