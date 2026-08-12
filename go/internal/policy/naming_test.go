package policy

import "testing"

// Les deux implémentations écrivent et lisent le MÊME répertoire, donc leurs
// noms de fichiers doivent coïncider au caractère près. Quand elles ont
// divergé — Python passé à une empreinte préfixée par longueur, Go resté sur
// une substitution de caractères — le service écrivait la décision de
// l'opérateur dans un fichier que le moteur n'ouvrait jamais : l'arbitrage
// passait par l'interface, annonçait un succès, et ne changeait rien.
// Silencieux, et sur la seule décision qu'on ne peut pas reprendre.
//
// Le défaut a vécu DEUX tours de revue parce qu'aucune des cinq preuves que je
// rejouais ne traversait le Go. Ces vecteurs sont produits par la fonction
// Python `_fichier_de_portee` ; `tests/test_parite_nommage.py` épingle les
// mêmes de son côté. Si l'une des deux dérive, l'une des deux rougit.
func TestNommageIdentiqueACeluiDePython(t *testing.T) {
	cas := []struct {
		scope, scopeKey, session, attendu string
	}{
		{"projet", "project:control-proof", "",
			"project-control-proof-061aed50418cd255.json"},
		{"session", "project:control-proof", "s-42",
			"project-control-proof-session-6cf7f5ee649ee882.json"},
		{"projet", "team/prod", "x", "team-prod-304a320b1e1c0edf.json"},
		{"session", "a:b/c", "", "a-b-c-session-9a18584f8d73ee66.json"},
		{"global", "peu:importe", "", "global.json"},
	}
	for _, c := range cas {
		p := New("/racine", c.scopeKey, c.session, []byte("peu-importe"))
		if got := p.file(c.scope); got != "/racine/"+c.attendu {
			t.Errorf("%s %q session=%q :\n  obtenu  %s\n  attendu /racine/%s",
				c.scope, c.scopeKey, c.session, got, c.attendu)
		}
	}
}
