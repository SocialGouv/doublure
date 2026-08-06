package policy

import (
	"fmt"
	"os"
	"strconv"
)

// Modes are named SETS of settings, never opaque behaviour.
//
// A mode does nothing a setting cannot: it sets several at once. That is what
// keeps it inspectable and overridable one setting at a time. A mode hiding
// logic would be a defect — you could neither read it nor deviate from it by
// one notch.
//
// No mode can open anything. They choose WHEN the operator is asked, never
// WHETHER protection applies: the default stays "anonymise" in all of them.
const (
	AnnounceSilent = "silencieux"
	AnnounceOn     = "annonce"

	ArbitrationDeferred = "differe"  // substitute, record, carry on
	ArbitrationBlocking = "bloquant" // wait for the decision before substituting

	DomainsRealTLD  = "tld_reels" // plausible (D1), collision possible
	DomainsReserved = "reserves"  // RFC 2606/6761: provably nobody's

	SettingArbitrationDelay = "delai_arbitrage"
)

var settingValues = map[string][]string{
	"annonce":          {AnnounceSilent, AnnounceOn},
	"arbitrage":        {ArbitrationDeferred, ArbitrationBlocking},
	"domaines_fictifs": {DomainsRealTLD, DomainsReserved},
}

// Settings in a stable order, so the interface always lists them the same way.
var Settings = []string{"annonce", "arbitrage", "domaines_fictifs", SettingArbitrationDelay}

var Modes = map[string]map[string]any{
	"auto": {
		"annonce": AnnounceOn, "arbitrage": ArbitrationDeferred,
		"domaines_fictifs": DomainsRealTLD, SettingArbitrationDelay: 0,
	},
	"consciencieux": {
		"annonce": AnnounceOn, "arbitrage": ArbitrationBlocking,
		"domaines_fictifs": DomainsReserved, SettingArbitrationDelay: 120,
	},
	"ferme": {
		"annonce": AnnounceSilent, "arbitrage": ArbitrationDeferred,
		"domaines_fictifs": DomainsReserved, SettingArbitrationDelay: 0,
	},
}

const DefaultMode = "auto"

// env holds the environment variable matching each setting. The environment
// always wins: it is the troubleshooting lever, so it must beat a file nobody
// thinks to re-read.
var env = map[string]string{
	"annonce":               "ANONPROXY_ANNONCE",
	"arbitrage":             "ANONPROXY_ARBITRAGE",
	"domaines_fictifs":      "ANONPROXY_DOMAINES_FICTIFS",
	SettingArbitrationDelay: "ANONPROXY_DELAI_ARBITRAGE",
}

// ValidateSetting normalises a value or refuses it.
func ValidateSetting(name string, value any) (any, error) {
	if name == SettingArbitrationDelay {
		seconds, err := toInt(value)
		if err != nil || seconds < 0 {
			return nil, fmt.Errorf("%w: %s expects a non-negative number of seconds, got %v",
				ErrInvalid, name, value)
		}
		return seconds, nil
	}
	allowed, ok := settingValues[name]
	if !ok {
		return nil, fmt.Errorf("%w: unknown setting %q", ErrInvalid, name)
	}
	s := fmt.Sprint(value)
	if !contains(allowed, s) {
		return nil, fmt.Errorf("%w: %s=%q unknown — expected one of %v",
			ErrInvalid, name, s, allowed)
	}
	return s, nil
}

func toInt(value any) (int, error) {
	switch v := value.(type) {
	case int:
		return v, nil
	case float64: // JSON numbers arrive as float64
		return int(v), nil
	default:
		return strconv.Atoi(fmt.Sprint(value))
	}
}

// Mode in force: nearest scope wins, environment beats all.
func (p *Policy) Mode() string {
	if forced := os.Getenv("ANONPROXY_MODE"); forced != "" {
		if _, ok := Modes[forced]; ok {
			return forced
		}
		fmt.Fprintf(os.Stderr, "anonproxy: unknown ANONPROXY_MODE %q — ignored\n", forced)
	}
	for i := len(Scopes) - 1; i >= 0; i-- {
		if named, ok := p.load(Scopes[i]).Settings["mode"].(string); ok {
			if _, known := Modes[named]; known {
				return named
			}
			fmt.Fprintf(os.Stderr, "anonproxy: unknown mode %q in %s — ignored\n",
				named, Scopes[i])
		}
	}
	return DefaultMode
}

// Setting resolves one setting: mode default → scopes → environment.
func (p *Policy) Setting(name string) any {
	if raw := os.Getenv(env[name]); raw != "" {
		if v, err := ValidateSetting(name, raw); err == nil {
			return v
		}
		fmt.Fprintf(os.Stderr, "anonproxy: %s=%q from the environment is invalid — ignored\n",
			env[name], raw)
	}
	for i := len(Scopes) - 1; i >= 0; i-- {
		if raw, ok := p.load(Scopes[i]).Settings[name]; ok {
			if v, err := ValidateSetting(name, raw); err == nil {
				return v
			}
			fmt.Fprintf(os.Stderr, "anonproxy: %s in %s is invalid — ignored\n", name, Scopes[i])
		}
	}
	return Modes[p.Mode()][name]
}

// ResolvedSettings is what actually applies, with the mode that set it.
func (p *Policy) ResolvedSettings() map[string]any {
	out := map[string]any{"mode": p.Mode()}
	for _, name := range Settings {
		out[name] = p.Setting(name)
	}
	return out
}

// SetSetting records a setting, or a whole mode.
func (p *Policy) SetSetting(scope, name string, value any) error {
	if !contains(Scopes, scope) {
		return fmt.Errorf("%w: unknown scope %q", ErrInvalid, scope)
	}
	normalised := value
	if name == "mode" {
		if _, ok := Modes[fmt.Sprint(value)]; !ok {
			return fmt.Errorf("%w: unknown mode %q", ErrInvalid, value)
		}
		normalised = fmt.Sprint(value)
	} else {
		var err error
		if normalised, err = ValidateSetting(name, value); err != nil {
			return err
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	l := p.load(scope)
	if l.Settings == nil {
		l.Settings = map[string]any{}
	}
	l.Settings[name] = normalised
	return p.save(scope, l)
}
