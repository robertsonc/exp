-- M3 p1: fleet API gaps (CR-wp5-fleet-api-gaps items 2, 5, 6). Forward-only, additive.

-- Item 6: the type of the component an issue is about (NULL for host-level issues). Stored, not joined, so it
-- survives deletion of the component.
ALTER TABLE issues ADD COLUMN component_type TEXT;
UPDATE issues SET component_type = (SELECT c.type FROM components c WHERE c.component_id = issues.component_id)
  WHERE component_id IS NOT NULL;

-- Item 2: latest per-probe rows of a collector (health metrics `probes[]`, at most 500). Latest values only:
-- every status report replaces the row; no history is kept.
CREATE TABLE component_probes_latest (
  component_id TEXT NOT NULL PRIMARY KEY,
  org_id TEXT NOT NULL DEFAULT 'default',
  reported_at TEXT NOT NULL,
  probes_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
