package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/sessions"
	"github.com/patrickmn/go-cache"
	"golang.org/x/oauth2"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	RdpGwSession = "RDPGWSESSION"
	MaxAge 		 = 120
)

type TokenGeneratorFunc func(context.Context, string, string) (string, error)
type UserTokenGeneratorFunc func(context.Context, string) (string, error)

type Config struct {
	SessionKey           []byte
	SessionEncryptionKey []byte
	PAATokenGenerator    TokenGeneratorFunc
	UserTokenGenerator   UserTokenGeneratorFunc
	OAuth2Config         *oauth2.Config
	store                *sessions.CookieStore
	OIDCTokenVerifier    *oidc.IDTokenVerifier
	stateStore           *cache.Cache
	GatewayAddress       string
	NetworkAutoDetect    int
	BandwidthAutoDetect  int
	ConnectionType       int
}

func (c *Config) NewApi() {
	if len(c.SessionKey) < 32 {
		log.Fatal("Session key too small")
	}
	c.store = sessions.NewCookieStore(c.SessionKey, c.SessionEncryptionKey)
	c.stateStore = cache.New(time.Minute*2, 5*time.Minute)
}

func (c *Config) HandleCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	s, found := c.stateStore.Get(state)
	if !found {
		http.Error(w, "unknown state", http.StatusBadRequest)
		return
	}
	url := s.(string)

	ctx := context.Background()
	oauth2Token, err := c.OAuth2Config.Exchange(ctx, r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
		return
	}
	idToken, err := c.OIDCTokenVerifier.Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	resp := struct {
		OAuth2Token   *oauth2.Token
		IDTokenClaims *json.RawMessage // ID Token payload is just JSON.
	}{oauth2Token, new(json.RawMessage)}

	if err := idToken.Claims(&resp.IDTokenClaims); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var data map[string]interface{}
	if err := json.Unmarshal(*resp.IDTokenClaims, &data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	session, err := c.store.Get(r, RdpGwSession)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	session.Options.MaxAge = MaxAge
	session.Values["preferred_username"] = data["preferred_username"]
	session.Values["authenticated"] = true
	session.Values["access_token"] = oauth2Token.AccessToken

	if err = session.Save(r, w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	http.Redirect(w, r, url, http.StatusFound)
}

func (c *Config) Authenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := c.store.Get(r, RdpGwSession)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		found := session.Values["authenticated"]
		if found == nil || !found.(bool) {
			seed := make([]byte, 16)
			rand.Read(seed)
			state := hex.EncodeToString(seed)
			c.stateStore.Set(state, r.RequestURI, cache.DefaultExpiration)
			http.Redirect(w, r, c.OAuth2Config.AuthCodeURL(state), http.StatusFound)
			return
		}

		ctx := context.WithValue(r.Context(), "preferred_username", session.Values["preferred_username"])
		ctx = context.WithValue(ctx, "access_token", session.Values["access_token"])

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (c *Config) HandleDownload(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userName, ok := ctx.Value("preferred_username").(string)

	if !ok {
		log.Printf("preferred_username not found in context")
		http.Error(w, errors.New("cannot find session or user").Error(), http.StatusInternalServerError)
		return
	}

	creds := strings.SplitN(userName, "@", 2)
	if len(creds) != 2 {
		log.Printf("preferred_username not found in context")
		http.Error(w, errors.New("cannot find session or user").Error(), http.StatusInternalServerError)
		return
	}
	user := creds[0]
	host := creds[1]

	token, err := c.PAATokenGenerator(ctx, user, host)
	if err != nil {
		log.Printf("Cannot generate PAA token for user %s due to %s", user, err)
		http.Error(w, errors.New("unable to generate gateway credentials").Error(), http.StatusInternalServerError)
	}

	// authenticated
	seed := make([]byte, 16)
	rand.Read(seed)
	fn := hex.EncodeToString(seed) + ".rdp"

	w.Header().Set("Content-Disposition", "attachment; filename="+fn)
	w.Header().Set("Content-Type", "application/x-rdp")
	data := "full address:s:"+host+"\r\n"+
		"gatewayhostname:s:"+c.GatewayAddress+"\r\n"+
		"gatewaycredentialssource:i:5\r\n"+
		"gatewayusagemethod:i:1\r\n"+
		"gatewayprofileusagemethod:i:1\r\n"+
		"gatewayaccesstoken:s:"+token+"\r\n"+
		"networkautodetect:i:"+strconv.Itoa(c.NetworkAutoDetect)+"\r\n"+
		"bandwidthautodetect:i:"+strconv.Itoa(c.BandwidthAutoDetect)+"\r\n"+
		"connection type:i:"+strconv.Itoa(c.ConnectionType)+"\r\n"+
		"username:s:"+user+"\r\n"+
		"domain:s:"+host+"\r\n"+
		"desktopwidth:i:1920\r\n"+
		"desktopheight:i:1080\r\n"+
		"screen mode id:i:1\r\n"

	http.ServeContent(w, r, fn, time.Now(), strings.NewReader(data))
}
