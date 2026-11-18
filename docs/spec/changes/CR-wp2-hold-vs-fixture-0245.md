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
