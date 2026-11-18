# CR-wp0-exm-fixture-readme-notes

**From:** WP-2 (collector) - **Affects:** WP-0 (`test/fixtures/exm/README.md`) - **Status:** informational, nothing blocks

Findings while replaying `outage-2026-10-27.ndjson.gz` through the exp rules; none needs a fixture change,
the golden tests (`collector/tests/golden/`) encode the corrected expectations.

1. **Times.** README times are EXM's: results stamped with their completion time (`emitted`), and the EXM DNS
   line also counted the scheduled `dns` test as DNS beats. exp stamps `ts` (start) and the spec's line table
   lists `dns_hb` only, so incident *starts* agree within 2 s but *ends* (first tick the line is good again)
   come up to ~10 s later (DNS: 03:51:24 vs 03:51:14, 04:06:44 vs 04:06:34). Wi-Fi: first failing record
   03:56:30 (README 03:56:34).
2. **"Must not page" blips.** The 02:45 `dns_hb` failure (110 s, every beat failing) does page when the
   replay starts before 02:55; EXM's replay loop began at 02:55. The golden test replays from 02:55 (as EXM)
   for the nine pages and asserts the 02:45 page separately. dhcp_hb blips and single Wi-Fi failures stay
   under their holds.
3. **Resolver kind.** At 04:21-04:23 the failing `dns_hb` records are labelled `resolver_kind: alternate`
   (converter rule: server 1.1.1.1), although in the recording 1.1.1.1 *was* the DHCP-given resolver at that
   time (EXM `resolver: "dhcp"`). The rules fall back to the alternate records when a beat has no DHCP-given
   record, which reproduces the page (`DNS`, start 04:21:32). A converter that kept EXM's `resolver` field as
   `resolver_kind` would be more faithful.
4. **Wi-Fi during the gateway outage.** README says wired and Wi-Fi both fail for the whole 03:00-03:43
   outage; the recording has the Wi-Fi laptop reaching the gateway again from ~03:12:42, so from then on the
   verdict is `switch` (wired ports fail, Wi-Fi reaches 10.1.0.1) while at 03:10 it is `gateway`.
5. Control-path traces and pings are absent, as README notes: `edge` / `isp` golden cases are synthetic
   (control traces added in the test).
