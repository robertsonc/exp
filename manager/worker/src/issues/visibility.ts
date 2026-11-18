// SQL predicate (alias `i`, `?1` = now ISO) for issues the UI and the platform webhook may show:
// open, not suppressed by an open host_offline of the same host, not snoozed.
export const VISIBLE_OPEN_SQL = `i.resolved_at IS NULL
  AND (i.kind = 'host_offline' OR NOT EXISTS (SELECT 1 FROM issues o WHERE o.host_id = i.host_id AND o.kind = 'host_offline' AND o.resolved_at IS NULL))
  AND NOT EXISTS (SELECT 1 FROM issue_snoozes s WHERE s.host_id = i.host_id AND s.kind = i.kind AND (s.until_resolved = 1 OR s.until > ?1))`;
