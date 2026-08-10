/**
 * anonproxy — confidentiality arbitration, inside the IDE.
 *
 * THIS EXTENSION PROTECTS NOTHING. It shows what the proxy anonymised and
 * carries the operator's decisions to the local control service. Protection
 * lives in the proxy: **uninstalling this must open nothing**. That is the
 * design test to repeat at every addition — if a feature here ever became
 * necessary to confidentiality, that would be the defect, not the feature.
 *
 * It talks to a UNIX SOCKET, never a port: a local port would be reachable by
 * the agent itself, and this API returns real values.
 *
 * State arrives by SERVER PUSH (SSE), not polling. That matters in exactly one
 * case, and it is the case that motivated the mode: in `consciencieux` the
 * request WAITS, so learning three seconds late that something is stuck on you
 * is three seconds of an agent doing nothing.
 *
 * Plain JavaScript, no build step: a thin extension does not deserve a
 * toolchain, and what is not compiled reads the way it runs.
 */
const http = require("http");
const os = require("os");
const path = require("path");
const vscode = require("vscode");

/**
 * The state directory of the open project.
 *
 * The same derivation as scripts/lib/state.sh and go/internal/guard/state.go:
 * one directory per project, named after the project's own path. The rule
 * lives in three places because three processes reach it independently — the
 * launcher, the hook that Claude Code starts, and this extension, which the
 * IDE starts with an environment none of the others control. A config file
 * would only move the problem: it would have to be found first.
 *
 * Zero configuration is the point. An arbitration surface nobody manages to
 * point at the right socket is an arbitration surface nobody uses, and the
 * operator then stops arbitrating — which is the one thing this whole system
 * asks of them.
 */
function slug(project) {
  return project.replace(/[^A-Za-z0-9_.]/g, "-");
}

function socketPath() {
  const configured = vscode.workspace.getConfiguration("anonproxy").get("socket");
  if (configured) return configured;
  if (process.env.ANONPROXY_STATE_DIR) {
    return path.join(process.env.ANONPROXY_STATE_DIR, "control.sock");
  }
  const folders = vscode.workspace.workspaceFolders;
  const project = folders && folders.length
    ? folders[0].uri.fsPath
    : process.cwd();
  return path.join(os.homedir(), ".anonshield", slug(project), "control.sock");
}

/** One-shot request. Resolves to null when the service is not listening. */
function call(method, route, body) {
  return new Promise((resolve) => {
    const payload = body ? JSON.stringify(body) : null;
    const req = http.request(
      { socketPath: socketPath(), path: route, method,
        headers: payload ? { "Content-Type": "application/json",
                             "Content-Length": Buffer.byteLength(payload) } : {} },
      (res) => {
        let raw = "";
        res.on("data", (c) => (raw += c));
        res.on("end", () => {
          try { resolve({ status: res.statusCode, body: JSON.parse(raw) }); }
          catch (_) { resolve({ status: res.statusCode, body: null }); }
        });
      });
    // Service absent: we surface "unknown", never something reassuring.
    req.on("error", () => resolve(null));
    if (payload) req.write(payload);
    req.end();
  });
}

/** What the operator may answer. "Reveal" is never preselected. */
const ANSWERS = [
  { label: "$(eye-closed) Keep anonymised", granularity: null },
  { label: "$(eye) Reveal THIS value", granularity: "valeur", decision: "reveler" },
  { label: "$(eye) Reveal this whole TYPE", granularity: "type", decision: "reveler" },
  { label: "$(shield) Stop asking for this TYPE",
    granularity: "type", decision: "anonymiser" },
  { label: "$(shield) Stop asking for this CLASS",
    granularity: "classe", decision: "anonymiser" },
];

const SCOPES = [
  { label: "projet", description: "applies to this project (default)" },
  { label: "session", description: "applies to this session only" },
  { label: "global", description: "applies everywhere — the default for projects" },
];

let latest = { settings: null, questions: [] };

/**
 * The queue, grouped by TYPE — the axis that turns hundreds of gestures into
 * a dozen. Opening is PROGRESSIVE by design: one type decision settles every
 * question of that type. Listing values flat hid that axis; measured on a real
 * sandbox, 462 values fell into 14 types. Largest groups first: that is where
 * one gesture pays most.
 */
function groupByType(questions) {
  const byType = new Map();
  for (const q of questions) {
    if (!byType.has(q.type)) byType.set(q.type, []);
    byType.get(q.type).push(q);
  }
  return [...byType.values()].sort((a, b) => b.length - a.length);
}

async function arbitrate() {
  const questions = latest.questions;
  if (!questions.length) {
    vscode.window.showInformationMessage("anonproxy: nothing waiting.");
    return;
  }
  // Groups are the DEFAULT, never a loss: "Show the N values" drops back to
  // one gesture per value. On a group, "Reveal THIS value" has no referent —
  // which is exactly what the detail option is for.
  const units = groupByType(questions);
  for (const group of units) {
    const q = group[0];
    const whole = group.length > 1;
    const answers = whole
      ? [...ANSWERS.filter((a) => a.granularity !== "valeur"),
         { label: `$(list-unordered) Show the ${group.length} values`,
           detail: true }]
      : ANSWERS;
    const preview = group.slice(0, 3)
      .map((x) => `${x.value} → ${x.surrogate}`).join("   ·   ");
    const choice = await vscode.window.showQuickPick(answers, {
      title: `anonproxy — ${q.class} · ${q.type}`
        + (whole ? `   (${group.length} values)` : ""),
      placeHolder: whole
        ? `${preview}${group.length > 3 ? `   …and ${group.length - 3} more` : ""}`
        : `${q.value}  →  sent as  ${q.surrogate}`,
      ignoreFocusOut: true,
    });
    if (!choice) return;                   // escaped: nothing is decided
    if (choice.detail) { units.push(...group.map((x) => [x])); continue; }
    if (!choice.granularity) continue;     // stays anonymised, asked again later

    const scope = await vscode.window.showQuickPick(SCOPES, {
      title: "Scope of the decision", ignoreFocusOut: true });
    if (!scope) continue;

    const target = { valeur: q.fingerprint, type: q.type, class: q.class,
                     classe: q.class }[choice.granularity];
    const res = await call("POST", "/decide", {
      granularity: choice.granularity, target,
      decision: choice.decision, scope: scope.label });
    if (!res || res.status >= 400) {
      const detail = res && res.body ? res.body.detail : "service unreachable";
      vscode.window.showErrorMessage(`anonproxy: refused — ${detail}`);
      continue;
    }
    if (res.body.warning) {
      // Revealing is irreversible in effect: it gets said.
      vscode.window.showWarningMessage(`anonproxy: ${res.body.warning}`);
    }
  }
}

async function chooseMode() {
  const health = await call("GET", "/health");
  if (!health || !health.body) {
    vscode.window.showWarningMessage("anonproxy: the control service is not listening.");
    return;
  }
  const modes = health.body.modes || {};
  const current = health.body.settings && health.body.settings.mode;
  const choice = await vscode.window.showQuickPick(
    Object.keys(modes).sort().map((name) => ({
      label: name + (name === current ? "  $(check)" : ""),
      name,
      detail: Object.entries(modes[name]).map(([k, v]) => `${k}=${v}`).join(" · "),
    })),
    { title: "anonproxy — mode (a mode is only a set of settings)" });
  if (!choice) return;
  const scope = await vscode.window.showQuickPick(SCOPES, { title: "Scope" });
  if (!scope) return;
  const res = await call("POST", "/settings",
                         { name: "mode", value: choice.name, scope: scope.label });
  if (!res || res.status >= 400) {
    vscode.window.showErrorMessage("anonproxy: could not change the mode.");
    return;
  }
  vscode.window.showInformationMessage(`anonproxy: mode ${choice.name} (${scope.label}).`);
}

/** Server-push stream, with reconnection. */
function connect(onState, onDown) {
  let stopped = false;
  let request = null;

  function open() {
    if (stopped) return;
    request = http.request(
      { socketPath: socketPath(), path: "/events", method: "GET" },
      (res) => {
        if (res.statusCode !== 200) { res.resume(); return retry(); }
        let buffer = "";
        res.setEncoding("utf8");
        res.on("data", (chunk) => {
          buffer += chunk;
          let cut;
          while ((cut = buffer.indexOf("\n\n")) >= 0) {
            const frame = buffer.slice(0, cut);
            buffer = buffer.slice(cut + 2);
            if (frame.startsWith(":")) continue;        // keep-alive
            const name = (frame.match(/^event: (.*)$/m) || [])[1];
            const data = (frame.match(/^data: (.*)$/m) || [])[1];
            if (name === "state" && data) {
              try { onState(JSON.parse(data)); } catch (_) { /* next frame */ }
            }
          }
        });
        res.on("end", retry);
        res.on("error", retry);
      });
    request.on("error", retry);
    request.end();
  }

  function retry() {
    if (stopped) return;
    onDown();
    // Fixed delay rather than backoff: the service is local, it either runs or
    // it does not, and a growing delay would only lengthen the blind window.
    setTimeout(open, 2000);
  }

  open();
  return () => { stopped = true; if (request) request.destroy(); };
}

function activate(context) {
  const item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  item.command = "anonproxy.arbitrate";
  item.show();
  context.subscriptions.push(item);

  let announced = 0;

  function render() {
    const { settings, questions } = latest;
    if (!settings) {
      item.text = "$(question) anonproxy: ?";
      item.tooltip = "Control service unreachable — the real state is unknown.";
      return;
    }
    // Le compteur annonce les GESTES, pas les valeurs : ce qui coûte à
    // l'opérateur est le nombre de décisions à prendre, et une décision de
    // type les règle toutes. Afficher 462 là où 14 gestes suffisent décourage
    // d'ouvrir la file — et une file jamais ouverte ne protège rien de plus.
    const groups = groupByType(questions);
    item.text = questions.length
      ? `$(shield) anonproxy ${settings.mode} · ${groups.length}`
      : `$(shield) anonproxy ${settings.mode}`;
    item.tooltip = new vscode.MarkdownString(
      [`**mode**: ${settings.mode}`,
       ...Object.entries(settings).filter(([k]) => k !== "mode")
         .map(([k, v]) => `**${k}**: ${v}`),
       "",
       `${questions.length} value(s) anonymised without an explicit rule, `
       + `in ${groups.length} type(s) — ${groups.length} decision(s) settle them all.`,
       ...groups.slice(0, 5).map((g) => `- ${g.length} × ${g[0].type}`),
       "",
       "_This extension enforces nothing: protection is in the proxy._"].join("\n\n"));
  }

  const disconnect = connect(
    async (state) => {
      latest = { settings: state.settings, questions: state.questions || [] };
      render();
      // Blocking mode makes the request WAIT. Without an alert the operator
      // does not know they are being waited on — the one gap this extension
      // genuinely closes.
      if (latest.questions.length > announced
          && latest.settings.arbitrage === "bloquant") {
        const action = await vscode.window.showWarningMessage(
          `anonproxy: ${latest.questions.length} value(s) awaiting your decision`
          + " — the request is on hold.", "Arbitrate");
        if (action === "Arbitrate") arbitrate();
      }
      announced = latest.questions.length;
    },
    () => { latest = { settings: null, questions: [] }; render(); announced = 0; });

  context.subscriptions.push({ dispose: disconnect });
  context.subscriptions.push(
    vscode.commands.registerCommand("anonproxy.arbitrate", arbitrate),
    vscode.commands.registerCommand("anonproxy.mode", chooseMode));
  render();
}

module.exports = { activate, deactivate() {} };
