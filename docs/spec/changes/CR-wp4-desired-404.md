# CR-wp4-desired-404: document 404 on GET /api/agent/v1/desired

- What: the manager returns 404 `not_found` from GET /desired when no desired state has been compiled for the host yet (e.g. host row exists but compile failed). agent.yaml lists only 200/304/401/429/503.
- Why: the manager cannot invent a document; 503 would mislead agents into backing off as if the service were down.
- Affected WPs: WP-0 (agent.yaml), WP-5 agent (treat 404 as "retry next poll").
- Compatibility: additive; agents that already treat unknown 4xx as a failed poll are unaffected.
