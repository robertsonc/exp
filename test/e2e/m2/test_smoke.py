def test_up(stack):
    r = stack.mgr.get("/healthz")
    assert r.status == 200
