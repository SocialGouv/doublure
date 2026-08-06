/**
 * Client Node de l'API d'arbitrage — le MÊME transport que l'extension.
 *
 * Tester l'API par le client Python prouverait la logique, pas le canal.
 * Ce script prouve qu'une socket Unix se parle bien depuis Node, ce dont
 * dépend toute l'extension.
 */
const http = require("http");

const socketPath = process.argv[2];

function appel(methode, chemin, corps) {
  return new Promise((resoudre, rejeter) => {
    const charge = corps ? JSON.stringify(corps) : null;
    const req = http.request(
      { socketPath, path: chemin, method: methode,
        headers: charge ? { "Content-Type": "application/json",
                            "Content-Length": Buffer.byteLength(charge) } : {} },
      (res) => {
        let brut = "";
        res.on("data", (c) => (brut += c));
        res.on("end", () => {
          try { resoudre({ statut: res.statusCode, corps: JSON.parse(brut) }); }
          catch (e) { rejeter(new Error(`réponse illisible : ${brut}`)); }
        });
      });
    req.on("error", rejeter);
    if (charge) req.write(charge);
    req.end();
  });
}

(async () => {
  const sante = await appel("GET", "/sante");
  console.log(`  santé  : mode=${sante.corps.reglages.mode}`
    + ` · ${sante.corps.questions} question(s) · coffre ${sante.corps.coffre}`);

  const { corps } = await appel("GET", "/questions");
  for (const q of corps.questions) {
    console.log(`  question : ${q.classe} · ${q.type} · ${q.valeur}`
      + `  →  ${q.substitut}`);
  }

  // D4 : l'API n'est PAS une dérogation. C'est le test qui compte le plus ici.
  const secret = await appel("POST", "/arbitrer",
    { granularite: "classe", cle: "secret", decision: "reveler", portee: "global" });
  if (secret.statut === 409) {
    console.log(`  REFUS-SECRET-OK : ${secret.corps.detail}`);
  } else {
    console.log(`  ÉCHEC : révéler un secret a été accepté (${secret.statut})`);
    process.exit(1);
  }

  const hote = corps.questions.find((q) => q.type === "HOSTNAME");
  const res = await appel("POST", "/arbitrer",
    { granularite: "valeur", cle: hote.empreinte, decision: "reveler",
      portee: "projet" });
  console.log(`  arbitré : ${res.statut} — ${res.corps.avertissement}`);
})().catch((e) => { console.error("  ERREUR :", e.message); process.exit(1); });
