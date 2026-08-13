package policy

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Les deux implémentations écrivent et lisent le MÊME répertoire, donc leurs
// noms de fichiers doivent coïncider au caractère près. Quand elles ont
// divergé — Python passé à une empreinte préfixée par longueur, Go resté sur
// une substitution de caractères — le service écrivait la décision de
// l'opérateur dans un fichier que le moteur n'ouvrait jamais : l'arbitrage
// passait par l'interface, annonçait un succès, et ne changeait rien.
// Silencieux, et sur la seule décision qu'on ne peut pas reprendre.
//
// Épingler des vecteurs de chaque côté n'a pas suffi : les cinq premiers
// portaient tous une clé de portée anodine, donc ils DÉFENDAIENT ce qu'ils
// vérifiaient sans COUVRIR la classe, et le préfixe lisible a continué de
// diverger — même empreinte, autre nom de fichier. Le corpus vit désormais
// dans UN fichier que les deux côtés lisent ; le Python exige en plus qu'il
// contienne un témoin du piège (une clé où tronquer et rogner ne commutent
// pas).
func TestNommageIdentiqueACeluiDePython(t *testing.T) {
	// Le corpus vit DANS le module, et c'est une contrainte de cache, pas un
	// choix de rangement : `go test` ne piste pas un fichier lu hors du module.
	// Placé sous `tests/`, il rendait `ok (cached)` sur un corpus délibérément
	// faux — un vert obtenu sans rien exécuter, sur la preuve même qui doit
	// détecter la divergence. Le Python lit celui-ci.
	brut, err := os.ReadFile("vecteurs_nommage.json")
	if err != nil {
		t.Fatalf("corpus partagé illisible : %v", err)
	}
	var cas []struct {
		Portee   string `json:"portee"`
		ScopeKey string `json:"scope_key"`
		Session  string `json:"session"`
		Attendu  string `json:"attendu"`
	}
	if err := json.Unmarshal(brut, &cas); err != nil {
		t.Fatalf("corpus partagé illisible : %v", err)
	}
	if len(cas) == 0 {
		t.Fatal("corpus vide : un test qui ne vérifie rien passe toujours")
	}
	for _, c := range cas {
		p := New("/racine", c.ScopeKey, c.Session, []byte("peu-importe"))
		if got := p.file(c.Portee); got != "/racine/"+c.Attendu {
			t.Errorf("%s %q session=%q :\n  obtenu  %s\n  attendu /racine/%s",
				c.Portee, c.ScopeKey, c.Session, got, c.Attendu)
		}
	}
}

// A message answer must land in the file Python reads, in the shape Python
// parses. `tests/control_e2e.sh` proves the crossing for real; this pins the
// shape so a change here goes red before it gets that far.
func TestAnswerForMessageShape(t *testing.T) {
	dir := t.TempDir()
	p := New(dir, "project:parity", "", []byte("d4d4"))
	if err := p.AnswerForMessage("type", "DATE", Reveal); err != nil {
		t.Fatalf("write refused: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "reponses-message.jsonl"))
	if err != nil {
		t.Fatalf("file Python reads is missing: %v", err)
	}
	var got map[string]string
	if err := json.Unmarshal(bytes.TrimSpace(raw), &got); err != nil {
		t.Fatalf("Python parses one JSON object per line: %v", err)
	}
	for k, want := range map[string]string{
		"granularite": "type", "cle": "DATE", "decision": "reveler",
	} {
		if got[k] != want {
			t.Errorf("field %q = %q, Python expects %q", k, got[k], want)
		}
	}
}

// D4 holds on THIS path too. A forgotten write path would open a secret, and
// the read guard on the engine side must not be the only thing standing.
func TestAnswerForMessageRefusesASecret(t *testing.T) {
	p := New(t.TempDir(), "project:parity", "", []byte("d4d4"))
	if err := p.AnswerForMessage("classe", "secret", Reveal); err == nil {
		t.Fatal("a secret was accepted for a message answer")
	}
	if err := p.AnswerForMessage("nawak", "x", Reveal); err == nil {
		t.Fatal("an unknown granularity was accepted")
	}
}
