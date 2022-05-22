package main

import (
	"context"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/api"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/common"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/config"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/protocol"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/security"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
	"log"
	"net/http"
	"strconv"
)

var cmd = &cobra.Command{
	Use:	"rdpgw",
	Long:	"Remote Desktop Gateway",
}

var (
	configFile	string
)

var conf config.Configuration

func main() {
	// get config
	cmd.PersistentFlags().StringVarP(&configFile, "conf", "c", "rdpgw.yaml",  "config file (json, yaml, ini)")
	conf = config.Load(configFile)

	security.VerifyClientIP = conf.Security.VerifyClientIp

	// set security keys
	security.SigningKey = []byte(conf.Security.PAATokenSigningKey)
	security.EncryptionKey = []byte(conf.Security.PAATokenEncryptionKey)
	security.UserEncryptionKey = []byte(conf.Security.UserTokenEncryptionKey)
	security.UserSigningKey = []byte(conf.Security.UserTokenSigningKey)

	// set oidc config
	provider, err := oidc.NewProvider(context.Background(), conf.OpenId.ProviderUrl)
	if err != nil {
		log.Fatalf("Cannot get oidc provider: %s", err)
	}
	oidcConfig := &oidc.Config{
		ClientID: conf.OpenId.ClientId,
	}
	verifier := provider.Verifier(oidcConfig)

	oauthConfig := oauth2.Config{
		ClientID: conf.OpenId.ClientId,
		ClientSecret: conf.OpenId.ClientSecret,
		RedirectURL: "https://" + conf.Server.GatewayAddress + "/callback",
		Endpoint: provider.Endpoint(),
		Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
	}
	security.OIDCProvider = provider
	security.Oauth2Config = oauthConfig

	api := &api.Config{
		GatewayAddress:       conf.Server.GatewayAddress,
		OAuth2Config:         &oauthConfig,
		OIDCTokenVerifier:    verifier,
		PAATokenGenerator:    security.GeneratePAAToken,
		UserTokenGenerator:   security.GenerateUserToken,
		SessionKey:           []byte(conf.Server.SessionKey),
		SessionEncryptionKey: []byte(conf.Server.SessionEncryptionKey),
		NetworkAutoDetect:    conf.Client.NetworkAutoDetect,
		BandwidthAutoDetect:  conf.Client.BandwidthAutoDetect,
		ConnectionType:       conf.Client.ConnectionType,
	}
	api.NewApi()

	//mux := http.NewServeMux()
	//mux.HandleFunc("*", HelloServer)

	log.Printf("Starting remote desktop gateway server")

	// create the gateway
	handlerConfig := protocol.ServerConf{
		IdleTimeout: conf.Caps.IdleTimeout,
		TokenAuth: conf.Caps.TokenAuth,
		SmartCardAuth: conf.Caps.SmartCardAuth,
		RedirectFlags: protocol.RedirectFlags{
			Clipboard: conf.Caps.EnableClipboard,
			Drive: conf.Caps.EnableDrive,
			Printer: conf.Caps.EnablePrinter,
			Port: conf.Caps.EnablePort,
			Pnp: conf.Caps.EnablePnp,
			DisableAll: conf.Caps.DisableRedirect,
			EnableAll: conf.Caps.RedirectAll,
		},
		VerifyTunnelCreate: security.VerifyPAAToken,
		VerifyServerFunc:   security.VerifyServerFunc,
		SendBuf:            conf.Server.SendBuf,
		ReceiveBuf:         conf.Server.ReceiveBuf,
	}
	gw := protocol.Gateway{
		ServerConf: &handlerConfig,
	}

	http.Handle("/remoteDesktopGateway/", common.EnrichContext(http.HandlerFunc(gw.HandleGatewayProtocol)))
	http.Handle("/connect", common.EnrichContext(api.Authenticated(http.HandlerFunc(api.HandleDownload))))
	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/tokeninfo", api.TokenInfo)
	http.HandleFunc("/callback", api.HandleCallback)

	err = http.ListenAndServe(":"+strconv.Itoa(conf.Server.Port), nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
