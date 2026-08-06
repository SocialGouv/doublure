/**
 * Node client for the control API — the SAME transport the extension uses.
 *
 * Testing the API from Python would prove the logic, not the channel. This
 * proves a Unix socket is reachable from Node, which the whole extension
 * depends on, and that the event stream really PUSHES.
 */
const http = require("http");

const socketPath = process.argv[2];

function call(method, path, body) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const req = http.request(
      { socketPath, path, method,
        headers: payload ? { "Content-Type": "application/json",
                             "Content-Length": Buffer.byteLength(payload) } : {} },
      (res) => {
        let raw = "";
        res.on("data", (c) => (raw += c));
        res.on("end", () => {
          try { resolve({ status: res.statusCode, body: JSON.parse(raw) }); }
          catch (e) { reject(new Error(`unreadable response: ${raw}`)); }
        });
      });
    req.on("error", reject);
    if (payload) req.write(payload);
    req.end();
  });
}

/** Opens the SSE stream and resolves on the Nth event. */
function stream(onEvent) {
  return new Promise((resolve, reject) => {
    const req = http.request({ socketPath, path: "/events", method: "GET" }, (res) => {
      let buffer = "";
      res.on("data", (chunk) => {
        buffer += chunk;
        let cut;
        while ((cut = buffer.indexOf("\n\n")) >= 0) {
          const frame = buffer.slice(0, cut);
          buffer = buffer.slice(cut + 2);
          if (frame.startsWith(":")) continue;          // keep-alive
          const name = (frame.match(/^event: (.*)$/m) || [])[1];
          const data = (frame.match(/^data: (.*)$/m) || [])[1];
          if (name && onEvent(name, data, () => { req.destroy(); resolve(); })) return;
        }
      });
      res.on("error", reject);
    });
    req.on("error", reject);
    req.end();
  });
}

(async () => {
  const health = await call("GET", "/health");
  console.log(`  health   : mode=${health.body.settings.mode}`
    + ` · ${health.body.questions} question(s) · vault ${health.body.vault}`);

  const { body } = await call("GET", "/questions");
  for (const q of body.questions) {
    console.log(`  question : ${q.class} · ${q.type} · ${q.value}  ->  ${q.surrogate}`);
  }

  // D4: the API is NOT a derogation. This is the test that matters most.
  const secret = await call("POST", "/decide", {
    granularity: "classe", target: "secret", decision: "reveler", scope: "global" });
  if (secret.status === 409) {
    console.log(`  SECRET-REFUSED-OK : ${secret.body.detail}`);
  } else {
    console.log(`  FAIL : revealing a secret was accepted (${secret.status})`);
    process.exit(1);
  }

  // The stream must PUSH: we open it, take the initial state, then trigger a
  // change from another request and wait to be told — never polling.
  const host = body.questions.find((q) => q.type === "HOSTNAME");
  let sawInitial = false;
  const pushed = stream((name, data, close) => {
    if (name === "state" && !sawInitial) {
      sawInitial = true;
      // Trigger the change only once the stream is established, otherwise we
      // could not tell a push from a lucky first read.
      call("POST", "/decide", { granularity: "valeur", target: host.fingerprint,
                                decision: "reveler", scope: "projet" })
        .then((r) => console.log(`  decided  : ${r.status} — ${r.body.warning}`));
      return false;
    }
    if (name === "state" && sawInitial) {
      const payload = JSON.parse(data);
      console.log(`  PUSH-OK  : stream pushed a new state`
        + ` (${payload.questions.length} question(s) left)`);
      close();
      return true;
    }
    return false;
  });

  const timeout = new Promise((_, reject) =>
    setTimeout(() => reject(new Error("no push within 10s")), 10000));
  await Promise.race([pushed, timeout]);
})().catch((e) => { console.error("  ERROR:", e.message); process.exit(1); });
