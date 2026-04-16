package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"

	echo "tls-fingerprint-echo/tls-fingerprint-echo"

	"github.com/psanford/tlsfingerprint/httpfingerprint"
)

func main() {
	cfg, err := echo.LoadConfig()
	if err != nil {
		log.Fatal(err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{echo.GenerateSelfSignedCert()},
		MinVersion:   tls.VersionTLS10,
	}

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Port))
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", echo.Handler)

	srv := httpfingerprint.NewServer()
	srv.HTTPServer = &http.Server{
		Handler:   mux,
		TLSConfig: tlsCfg,
	}

	log.Printf("Listening on https://localhost:%d", cfg.Port)
	log.Fatal(srv.Serve(ln))
}
