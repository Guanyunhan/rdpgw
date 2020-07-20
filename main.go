package main

import (
	"context"
	"crypto/tls"
	"github.com/bolkedebruin/rdpgw/config"
	"github.com/bolkedebruin/rdpgw/protocol"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/patrickmn/go-cache"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

var cmd = &cobra.Command{
	Use:	"rdpgw",
	Long:	"Remote Desktop Gateway",
}

var (
	configFile	string
)

var tokens = cache.New(time.Minute *5, 10*time.Minute)
var conf config.Configuration

var verifier *oidc.IDTokenVerifier
var oauthConfig oauth2.Config
var ctx context.Context

func main() {
	// get config
	cmd.PersistentFlags().StringVarP(&configFile, "conf", "c", "rdpgw.yaml",  "config file (json, yaml, ini)")
	conf = config.Load(configFile)

	// set oidc config
	ctx = context.Background()
	provider, err := oidc.NewProvider(ctx, conf.OpenId.ProviderUrl)
	if err != nil {
		log.Fatalf("Cannot get oidc provider: %s", err)
	}
	oidcConfig := &oidc.Config{
		ClientID: conf.OpenId.ClientId,
	}
	verifier = provider.Verifier(oidcConfig)

	oauthConfig = oauth2.Config{
		ClientID: conf.OpenId.ClientId,
		ClientSecret: conf.OpenId.ClientSecret,
		RedirectURL: "https://" + conf.Server.GatewayAddress + "/callback",
		Endpoint: provider.Endpoint(),
		Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
	}

	if conf.Server.CertFile == "" || conf.Server.KeyFile == "" {
		log.Fatal("Both certfile and keyfile need to be specified")
	}

	//mux := http.NewServeMux()
	//mux.HandleFunc("*", HelloServer)

	log.Printf("Starting remote desktop gateway server")

	cfg := &tls.Config{}
	tlsDebug := os.Getenv("SSLKEYLOGFILE")
	if tlsDebug != "" {
		w, err := os.OpenFile(tlsDebug, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			log.Fatalf("Cannot open key log file %s for writing %s", tlsDebug, err)
		}
		log.Printf("Key log file set to: %s", tlsDebug)
		cfg.KeyLogWriter = w
	}


	cert, err := tls.LoadX509KeyPair(conf.Server.CertFile, conf.Server.KeyFile)
	if err != nil {
		log.Fatal(err)
	}
	cfg.Certificates = append(cfg.Certificates, cert)
	server := http.Server{
		Addr:      ":" + strconv.Itoa(conf.Server.Port),
		TLSConfig: cfg,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)), // disable http2
	}

	http.HandleFunc("/remoteDesktopGateway/", protocol.HandleGatewayProtocol)
	http.HandleFunc("/connect", handleRdpDownload)
	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/callback", handleCallback)

	err = server.ListenAndServeTLS("", "")
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
