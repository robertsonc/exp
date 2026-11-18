# CR-wp4-rotate-409-code

What: test/fakes/fake_manager.py (line ~433) returns 409 code `no_rotate_action` for POST /rotate with no rotate_agent_secret action; shared/openapi/agent.yaml specifies `rotation_not_requested`.
Why: the OpenAPI spec is the contract; the real manager (WP-4) now emits `rotation_not_requested`.
Affected WPs: WP-0 (fake_manager), WP-5 agent tests if they assert the code string.
Compatibility: change the string in the fake only; field names and status (409) are unchanged.
