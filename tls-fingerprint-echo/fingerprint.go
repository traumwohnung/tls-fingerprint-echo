package echo

import (
	"encoding/json"
	"net/http"

	"github.com/Easonliuliang/helloprint/database"
	"github.com/Easonliuliang/helloprint/match"
	"github.com/psanford/tlsfingerprint/httpfingerprint"
)

var db = database.Default()

type TLSFingerprint struct {
	JA3Hash string `json:"ja3_hash"`
	JA3Raw  string `json:"ja3_raw"`
	JA4     string `json:"ja4"`
}

type TLSVerdict struct {
	Level              string   `json:"level"`
	Score              float64  `json:"score"`
	Reasons            []string `json:"reasons"`
	UAMatches          []string `json:"ua_matches"`
	FingerprintMatches []string `json:"fingerprint_matches"`
}

type Response struct {
	RemoteAddr             string         `json:"remote_addr"`
	UserAgent              string         `json:"user_agent"`
	Fingerprint            TLSFingerprint `json:"fingerprint"`
	Verdict                TLSVerdict     `json:"verdict"`
	HTTPCloakPresetMatches []PresetMatch  `json:"httpcloak_preset_matches"`
}

func ExtractFingerprint(r *http.Request) Response {
	resp := Response{
		RemoteAddr: r.RemoteAddr,
		UserAgent:  r.UserAgent(),
	}

	if fp := httpfingerprint.FingerprintFromContext(r.Context()); fp != nil {
		resp.Fingerprint = TLSFingerprint{
			JA3Hash: fp.JA3Hash(),
			JA3Raw:  fp.JA3String(),
			JA4:     fp.JA4String(),
		}
	}

	v := match.CheckConsistency(resp.UserAgent, resp.Fingerprint.JA3Hash, resp.Fingerprint.JA4, db)
	resp.Verdict = TLSVerdict{
		Level:              string(v.Level),
		Score:              v.Score,
		Reasons:            v.Reasons,
		UAMatches:          v.UAMatches,
		FingerprintMatches: v.FingerprintMatches,
	}
	resp.HTTPCloakPresetMatches = MatchingPresets(v.FingerprintMatches)

	return resp
}

func Handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ExtractFingerprint(r))
}
