package policy

import (
	"encoding/json"
	"os"
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
