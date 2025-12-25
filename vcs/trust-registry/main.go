package main

import (
	"flag"
	"log"
	"os"
)

func main() {
	var (
		addr     = flag.String("addr", envOr("TR_ADDR", ":8098"), "listen address")
		allowAll = flag.Bool("allow-all", envOrBool("TR_ALLOW_ALL", true), "allow all wallets (ignore trust list)")
		tlsCert  = flag.String("tls-cert", os.Getenv("TR_TLS_CERT"), "path to TLS cert (optional)")
		tlsKey   = flag.String("tls-key", os.Getenv("TR_TLS_KEY"), "path to TLS key (optional)")
	)
	flag.Parse()

	cfg := Config{
		Addr:     *addr,
		AllowAll: *allowAll,
		TLSCert:  *tlsCert,
		TLSKey:   *tlsKey,
	}

	srv := NewServer(cfg)

	log.Printf("trust-registry listening on %s (allow-all=%v, tls=%v)", cfg.Addr, cfg.AllowAll, cfg.TLSCert != "" && cfg.TLSKey != "")
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envOrBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	switch v {
	case "1", "true", "TRUE", "yes", "YES", "y", "Y":
		return true
	case "0", "false", "FALSE", "no", "NO", "n", "N":
		return false
	default:
		return def
	}
}
