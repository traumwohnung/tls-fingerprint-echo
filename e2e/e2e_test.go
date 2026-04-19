package e2e_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak"
)

type serverResponse struct {
	RemoteAddr  string `json:"remote_addr"`
	UserAgent   string `json:"user_agent"`
	Fingerprint struct {
		JA3Hash string `json:"ja3_hash"`
		JA3Raw  string `json:"ja3_raw"`
		JA4     string `json:"ja4"`
	} `json:"fingerprint"`
	UAConsistent bool `json:"ua_consistent"`
}

func TestMain(m *testing.M) {
	build := exec.Command("go", "build", "-o", "tls-fingerprint-echo-test", "tls-fingerprint-echo/cmd/tls-fingerprint-echo")
	build.Stdout = os.Stdout
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "build failed: %v\n", err)
		os.Exit(1)
	}
	defer os.Remove("tls-fingerprint-echo-test")

	os.Exit(m.Run())
}

func startServer(t *testing.T) (baseURL string, stop func()) {
	t.Helper()

	port := freePort(t)
	cmd := exec.Command("./tls-fingerprint-echo-test")
	cmd.Env = append(os.Environ(), fmt.Sprintf("PORT=%d", port))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}

	addr := fmt.Sprintf("localhost:%d", port)
	waitForPort(t, addr, 5*time.Second)

	return fmt.Sprintf("https://%s", addr), func() { cmd.Process.Kill() }
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

func waitForPort(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()
	tlsCfg := &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := tls.DialWithDialer(
			&net.Dialer{Timeout: 100 * time.Millisecond},
			"tcp", addr, tlsCfg,
		)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("server at %s did not start within %s", addr, timeout)
}

func request(t *testing.T, url, preset string) serverResponse {
	t.Helper()
	session := httpcloak.NewSession(preset, httpcloak.WithInsecureSkipVerify())
	defer session.Close()

	resp, err := session.Get(context.Background(), url)
	if err != nil {
		t.Fatalf("GET %s (preset=%s): %v", url, preset, err)
	}
	defer resp.Close()

	body, err := resp.Bytes()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	var sr serverResponse
	if err := json.Unmarshal(body, &sr); err != nil {
		t.Fatalf("unmarshal response: %v\nbody: %s", err, body)
	}
	return sr
}

func TestFingerprintIsPresent(t *testing.T) {
	url, stop := startServer(t)
	defer stop()

	for _, preset := range []string{"chrome-latest", "firefox-latest", "safari-latest"} {
		t.Run(preset, func(t *testing.T) {
			sr := request(t, url, preset)

			if sr.Fingerprint.JA3Hash == "" {
				t.Error("ja3_hash is empty")
			}
			if sr.Fingerprint.JA3Raw == "" {
				t.Error("ja3_raw is empty")
			}
			if sr.Fingerprint.JA4 == "" {
				t.Error("ja4 is empty")
			}
		})
	}
}

func TestUAConsistent(t *testing.T) {
	url, stop := startServer(t)
	defer stop()

	for _, preset := range []string{"chrome-latest", "firefox-latest", "safari-latest"} {
		t.Run(preset, func(t *testing.T) {
			sr := request(t, url, preset)
			if !sr.UAConsistent {
				t.Errorf("expected ua_consistent=true for preset %s (ua=%q)", preset, sr.UserAgent)
			}
		})
	}
}

func TestFingerprintsDifferAcrossPresets(t *testing.T) {
	url, stop := startServer(t)
	defer stop()

	presets := []string{"chrome-latest", "firefox-latest", "safari-latest"}
	hashes := make(map[string]string, len(presets))

	for _, preset := range presets {
		sr := request(t, url, preset)
		hashes[preset] = sr.Fingerprint.JA3Hash
	}

	seen := map[string]string{}
	for preset, hash := range hashes {
		if other, exists := seen[hash]; exists {
			t.Errorf("presets %q and %q produced the same JA3 hash %q", preset, other, hash)
		}
		seen[hash] = preset
	}
}
