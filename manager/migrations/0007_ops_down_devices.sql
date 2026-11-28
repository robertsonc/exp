-- Ops board: the devices that are DOWN, so the board and the read-only /kiosk can say what to go and look at.
-- Forward-only. Stored per platform (ops_device_status.kind), at most 500 entries, longest down first:
--   [{"k": <24-hex keyed hash of the vendor identity>, "n": <name|null>, "t": "ap"|"switch"|"gateway"|"other",
--     "s": <site name|null>, "since": <ISO-8601 UTC>}]
-- Only devices that are down; never the whole inventory, a serial, a MAC, an address or a credential. The hash exists
-- only so "down since" survives from one poll to the next. A connector change (config_fp) empties the list.
ALTER TABLE ops_device_status ADD COLUMN down_json TEXT NOT NULL DEFAULT '[]';
