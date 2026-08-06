/**
 * anonproxy — arbitrage de confidentialité, dans l'IDE.
 *
 * CETTE EXTENSION NE PROTÈGE RIEN. Elle affiche ce que le proxy a anonymisé et
 * transmet les décisions de l'opérateur à l'API locale. La protection vit dans
 * le proxy : **la désinstaller ne doit rien ouvrir**. C'est le test de
 * conception à repasser à chaque ajout — si une fonctionnalité d'ici devenait
 * nécessaire à la confidentialité, ce serait le défaut, pas la fonctionnalité.
 *
 * Elle parle à une SOCKET UNIX, jamais à un port : un port local serait
 * joignable par l'agent lui-même, et cette API rend les valeurs réelles.
 *
 * JavaScript simple, sans étape de compilation : une extension mince ne mérite
 * pas une chaîne de build, et ce qui n'est pas compilé se relit tel qu'il
 * s'exécute.
 */
const http = require("http");
const os = require("os");
const path = require("path");
const vscode = require("vscode");

/** Chemin par défaut de la socket — le même que celui calculé côté Python. */
function socketParDefaut() {
  const configure = vscode.workspace.getConfiguration("anonproxy").get("socket");
  if (configure) return configure;
  const etat = process.env.ANONPROXY_STATE_DIR
    || path.join(os.homedir(), ".local", "state", "anonproxy");
  return path.join(etat, "arbitrage.sock");
}

/** Appel HTTP sur la socket Unix. Rend `null` si l'API n'écoute pas. */
function appel(methode, chemin, corps) {
  return new Promise((resoudre) => {
    const charge = corps ? JSON.stringify(corps) : null;
    const req = http.request(
      {
        socketPath: socketParDefaut(),
        path: chemin,
        method: methode,
        headers: charge
          ? { "Content-Type": "application/json",
              "Content-Length": Buffer.byteLength(charge) }
          : {},
      },
      (res) => {
        let brut = "";
        res.on("data", (c) => (brut += c));
        res.on("end", () => {
          try {
            resoudre({ statut: res.statusCode, corps: JSON.parse(brut) });
          } catch (_) {
            resoudre({ statut: res.statusCode, corps: null });
          }
        });
      }
    );
    // API absente = on n'affiche rien de rassurant : l'état devient « inconnu ».
    req.on("error", () => resoudre(null));
    if (charge) req.write(charge);
    req.end();
  });
}

/** Ce que l'opérateur peut répondre. « Révéler » n'est jamais présélectionné. */
const REPONSES = [
  { label: "$(eye-closed) Laisser anonymisé", granularite: null },
  { label: "$(eye) Révéler CETTE valeur", granularite: "valeur", decision: "reveler" },
  { label: "$(eye) Révéler tout ce TYPE", granularite: "type", decision: "reveler" },
  { label: "$(shield) Ne plus demander pour ce TYPE",
    granularite: "type", decision: "anonymiser" },
  { label: "$(shield) Ne plus demander pour cette CLASSE",
    granularite: "classe", decision: "anonymiser" },
];

const PORTEES = [
  { label: "projet", description: "vaut pour ce projet (défaut)" },
  { label: "session", description: "vaut pour cette session seulement" },
  { label: "global", description: "vaut partout — sert de défaut aux projets" },
];

async function arbitrer() {
  const reponse = await appel("GET", "/questions");
  if (!reponse) {
    vscode.window.showWarningMessage(
      "anonproxy : l'API d'arbitrage n'écoute pas (scripts/run-policy-api.sh)."
    );
    return;
  }
  const questions = (reponse.corps && reponse.corps.questions) || [];
  if (questions.length === 0) {
    vscode.window.showInformationMessage("anonproxy : aucune question en attente.");
    return;
  }

  for (const q of questions) {
    const choix = await vscode.window.showQuickPick(
      REPONSES.map((r) => ({ ...r, detail: undefined })),
      {
        title: `anonproxy — ${q.classe} · ${q.type}`,
        placeHolder: `${q.valeur}  →  envoyé sous  ${q.substitut}`,
        ignoreFocusOut: true,
      }
    );
    if (!choix) return;                    // échappement : on ne décide rien
    if (!choix.granularite) continue;      // reste anonymisé, sera reproposé

    const portee = await vscode.window.showQuickPick(PORTEES, {
      title: "Portée de la décision",
      ignoreFocusOut: true,
    });
    if (!portee) continue;

    const cle = { valeur: q.empreinte, type: q.type, classe: q.classe }[choix.granularite];
    const res = await appel("POST", "/arbitrer", {
      granularite: choix.granularite,
      cle,
      decision: choix.decision,
      portee: portee.label,
    });
    if (!res || res.statut >= 400) {
      const detail = res && res.corps ? res.corps.detail : "API injoignable";
      vscode.window.showErrorMessage(`anonproxy : refusé — ${detail}`);
      continue;
    }
    if (res.corps.avertissement) {
      // Une révélation est irréversible dans ses effets : elle se dit.
      vscode.window.showWarningMessage(`anonproxy : ${res.corps.avertissement}`);
    }
  }
}

async function changerDeMode() {
  const sante = await appel("GET", "/sante");
  if (!sante || !sante.corps) {
    vscode.window.showWarningMessage("anonproxy : l'API d'arbitrage n'écoute pas.");
    return;
  }
  const modes = sante.corps.modes || {};
  const courant = sante.corps.reglages && sante.corps.reglages.mode;
  const choix = await vscode.window.showQuickPick(
    Object.keys(modes).sort().map((nom) => ({
      label: nom + (nom === courant ? "  $(check)" : ""),
      nom,
      detail: Object.entries(modes[nom]).map(([k, v]) => `${k}=${v}`).join(" · "),
    })),
    { title: "anonproxy — mode (un mode n'est qu'un jeu de réglages)" }
  );
  if (!choix) return;
  const portee = await vscode.window.showQuickPick(PORTEES, { title: "Portée" });
  if (!portee) return;
  const res = await appel("POST", "/reglages",
                          { nom: "mode", valeur: choix.nom, portee: portee.label });
  if (!res || res.statut >= 400) {
    vscode.window.showErrorMessage("anonproxy : le changement de mode a échoué.");
    return;
  }
  vscode.window.showInformationMessage(`anonproxy : mode ${choix.nom} (${portee.label}).`);
}

function activate(contexte) {
  const barre = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Right, 100);
  barre.command = "anonproxy.arbitrer";
  contexte.subscriptions.push(barre);

  let dejaSignalees = 0;
  async function releve() {
    const sante = await appel("GET", "/sante");
    if (!sante || !sante.corps) {
      // Ne JAMAIS afficher un état rassurant qu'on n'a pas constaté.
      barre.text = "$(question) anonproxy : ?";
      barre.tooltip = "API d'arbitrage injoignable — l'état réel est inconnu.";
      barre.show();
      dejaSignalees = 0;
      return;
    }
    const { reglages, questions } = sante.corps;
    barre.text = questions > 0
      ? `$(shield) anonproxy ${reglages.mode} · ${questions}`
      : `$(shield) anonproxy ${reglages.mode}`;
    barre.tooltip = new vscode.MarkdownString(
      [`**mode** : ${reglages.mode}`,
       ...Object.entries(reglages).filter(([k]) => k !== "mode")
         .map(([k, v]) => `**${k}** : ${v}`),
       "",
       `${questions} valeur(s) anonymisée(s) sans règle explicite.`,
       "",
       "_L'extension n'applique rien : la protection est dans le proxy._"].join("\n\n"));
    barre.show();

    // Le mode bloquant fait ATTENDRE la requête : sans alerte, l'opérateur ne
    // sait pas qu'on l'attend. C'est le seul manque vraiment structurel que
    // cette extension comble.
    if (questions > dejaSignalees && reglages.arbitrage === "bloquant") {
      const action = await vscode.window.showWarningMessage(
        `anonproxy : ${questions} valeur(s) attendent ton arbitrage — la requête est en attente.`,
        "Arbitrer");
      if (action === "Arbitrer") arbitrer();
    }
    dejaSignalees = questions;
  }

  const secondes = vscode.workspace.getConfiguration("anonproxy")
    .get("intervalleSondage") || 3;
  const minuteur = setInterval(releve, secondes * 1000);
  contexte.subscriptions.push({ dispose: () => clearInterval(minuteur) });
  releve();

  contexte.subscriptions.push(
    vscode.commands.registerCommand("anonproxy.arbitrer", arbitrer),
    vscode.commands.registerCommand("anonproxy.mode", changerDeMode));
}

module.exports = { activate, deactivate() {} };
