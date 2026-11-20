/* exp speed check: internet-leg engine host (CR-m6-speedtest-server item 9). One file, two modes:
 *  - inside a DedicatedWorkerGlobalScope (the normal case) it answers postMessage commands from the page so the vendored engine's
 *    request/response work (string upload bodies are encoded synchronously by fetch()) never runs on the page's main thread;
 *  - on the main thread (the fallback when workers are unavailable) it only exposes the engine as window.CFSpeedTest.
 * The vendored @cloudflare/speedtest sits between this prelude and the bridge unmodified. It reads window.location.origin only. */
var EXP_IN_WORKER = typeof WorkerGlobalScope !== "undefined" && typeof self !== "undefined" && self instanceof WorkerGlobalScope;
if (EXP_IN_WORKER) { self.window = self; }
