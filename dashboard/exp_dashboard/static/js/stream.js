// SSE client for /api/v1/stream with reconnect (backoff + jitter) and a connected/disconnected signal.
import { qs } from "./api.js";

export class Live {
  // query: {probes: "a,b"} or {site: "x"}; handlers: {beat, state, incident, collector, status(up:boolean), reconnected()}
  constructor(query, handlers) {
    this.url = "/api/v1/stream" + qs(query);
    this.h = handlers || {};
    this.es = null;
    this.up = false;
    this.closed = false;
    this.timer = null;
    this.delay = 1000;
    this.everUp = false;
    this.open();
  }

  open() {
    if (this.closed) return;
    const es = new EventSource(this.url);
    this.es = es;
    es.addEventListener("open", () => {
      this.delay = 1000;
      const again = this.everUp;
      this.everUp = true;
      this.set(true);
      if (again && this.h.reconnected) this.h.reconnected();
    });
    for (const kind of ["beat", "state", "incident", "collector"]) {
      es.addEventListener(kind, (ev) => {
        let doc;
        try {
          doc = JSON.parse(ev.data);
        } catch (e) {
          return;
        }
        if (doc && typeof doc === "object" && this.h[kind]) this.h[kind](doc);
      });
    }
    es.addEventListener("error", () => {
      this.set(false);
      if (es.readyState === EventSource.CLOSED) this.retry();
    });
  }

  retry() {
    if (this.closed || this.timer) return;
    if (this.es) this.es.close();
    const wait = this.delay * (0.75 + Math.random() * 0.5);
    this.delay = Math.min(this.delay * 2, 15000);
    this.timer = setTimeout(() => { this.timer = null; this.open(); }, wait);
  }

  set(up) {
    if (up === this.up) return;
    this.up = up;
    if (this.h.status) this.h.status(up);
  }

  close() {
    this.closed = true;
    if (this.timer) clearTimeout(this.timer);
    if (this.es) this.es.close();
  }
}
