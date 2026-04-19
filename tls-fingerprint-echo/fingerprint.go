package echo

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/psanford/tlsfingerprint/httpfingerprint"
	"github.com/ua-parser/uap-go/uaparser"
)

var uaParser = uaparser.NewFromSaved()

// knownBrowserFamilies is the set of browser families considered "real browsers".
var knownBrowserFamilies = map[string]bool{
	"chrome":         true,
	"chrome mobile":  true,
	"chromium":       true,
	"firefox":        true,
	"firefox mobile": true,
	"safari":         true,
	"mobile safari":  true,
	"edge":           true,
}

type TLSFingerprint struct {
	JA3Hash string `json:"ja3_hash"`
	JA3Raw  string `json:"ja3_raw"`
	JA4     string `json:"ja4"`
}

type Response struct {
	RemoteAddr   string         `json:"remote_addr"`
	UserAgent    string         `json:"user_agent"`
	Fingerprint  TLSFingerprint `json:"fingerprint"`
	UAConsistent bool           `json:"ua_consistent"`
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

	// UAConsistent is true when the User-Agent parses to a known browser family.
	parsed := uaParser.Parse(resp.UserAgent)
	family := strings.ToLower(parsed.UserAgent.Family)
	resp.UAConsistent = knownBrowserFamilies[family]

	return resp
}

func Handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ExtractFingerprint(r))
}
