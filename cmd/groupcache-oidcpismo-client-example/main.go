// Package main implements the tool.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"maps"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/udhos/groupcache_oidcpismo/oidc"
	"github.com/udhos/oidcpismo/oidcpismo"
)

type application struct {
	tokenURL          string
	targetURL         string
	targetMethod      string
	targetBody        string
	count             int
	softExpireSeconds int
	interval          time.Duration
	concurrent        bool
	debug             bool
	purgeExpired      bool
	privKeyFile       string

	pismoTenantID     string
	pismoAccountID    string
	pismoClaims       string
	pismoCustomClaims string
	pismoIssuer       string
	pismoSubject      string
	pismoAudience     string
	pismoExpire       time.Duration
}

func main() {

	app := application{}

	flag.StringVar(&app.tokenURL, "tokenURL", "http://localhost:8080/token", "token URL")
	flag.StringVar(&app.targetURL, "targetURL", "https://httpbin.org/get", "target URL")
	flag.StringVar(&app.targetMethod, "targetMethod", "GET", "target method")
	flag.StringVar(&app.targetBody, "targetBody", "targetBody", "target body")
	flag.IntVar(&app.count, "count", 2, "how many requests to send")
	flag.IntVar(&app.softExpireSeconds, "softExpireSeconds", 10, "token soft expire in seconds")
	flag.DurationVar(&app.interval, "interval", 2*time.Second, "interval between sends")
	flag.BoolVar(&app.concurrent, "concurrent", false, "concurrent requests")
	flag.BoolVar(&app.debug, "debug", false, "enable debug logging")
	flag.BoolVar(&app.purgeExpired, "purgeExpired", true, "purge all expired items when the oldest item is removed")
	flag.StringVar(&app.privKeyFile, "privKeyFile", "oidc/testdata/key-priv.pem", "private key file for signing tokens")

	flag.StringVar(&app.pismoTenantID, "pismoTenantID", "tenant123", "pismo tenant ID")
	flag.StringVar(&app.pismoAccountID, "pismoAccountID", "account123", "pismo account ID")
	flag.StringVar(&app.pismoClaims, "pismoClaims", `{"group": "pismo-v1:some-samplegroup:rw"}`, "pismo claims")
	flag.StringVar(&app.pismoCustomClaims, "pismoCustomClaims", `{"custom1":"someValue","userexample": "user@user.com"}`, "pismo custom claims")
	flag.StringVar(&app.pismoIssuer, "pismoIssuer", "issuer", "pismo issuer")
	flag.StringVar(&app.pismoSubject, "pismoSubject", "subject", "pismo subject")
	flag.StringVar(&app.pismoAudience, "pismoAudience", "audience", "pismo audience")
	flag.DurationVar(&app.pismoExpire, "pismoExpire", time.Minute, "pismo expire duration")

	flag.Parse()

	// load private key
	privKeyPem, errRead := os.ReadFile(app.privKeyFile)
	if errRead != nil {
		log.Fatalf("failed to read private key file: %s: %v",
			app.privKeyFile, errRead)
	}
	privKey, errParse := jwt.ParseRSAPrivateKeyFromPEM(privKeyPem)
	if errParse != nil {
		log.Fatalf("failed to parse private key: %v", errParse)
	}

	groupcacheWorkspace := startGroupcache()

	var pisomoClaims map[string]any
	var pisomoCustomClaims map[string]any

	errClaims := json.Unmarshal([]byte(app.pismoClaims), &pisomoClaims)
	if errClaims != nil {
		log.Fatalf("failed to unmarshal pismoClaims: %v", errClaims)
	}

	errCustomClaims := json.Unmarshal([]byte(app.pismoCustomClaims), &pisomoCustomClaims)
	if errCustomClaims != nil {
		log.Fatalf("failed to unmarshal pismoCustomClaims: %v", errCustomClaims)
	}

	opt := oidcpismo.Options{
		TokenURL: app.tokenURL,
		Client:   http.DefaultClient,
		PrivKey:  privKey,

		TenantID:     app.pismoTenantID,
		UID:          app.pismoAccountID,
		Pismo:        pisomoClaims,
		CustomClaims: pisomoCustomClaims,

		Issuer:   app.pismoIssuer,
		Subject:  app.pismoSubject,
		Audience: app.pismoAudience,
		Expire:   app.pismoExpire,
	}

	options := oidc.Options{
		Options:             opt,
		SoftExpireInSeconds: app.softExpireSeconds,
		GroupcacheWorkspace: groupcacheWorkspace,
		DisablePurgeExpired: !app.purgeExpired,
		Debug:               app.debug,
	}

	client := oidc.New(options)

	metrics(groupcacheWorkspace)

	h := http.Header{}
	h.Add("x-account-id", app.pismoAccountID)

	if app.concurrent {
		//
		// concurrent requests
		//
		var wg sync.WaitGroup
		for i := 1; i <= app.count; i++ {
			j := i
			wg.Go(func() {
				send(&app, client, h, j)
			})
		}
		wg.Wait()
		return
	}

	//
	// non-concurrent requests
	//
	for i := 1; i <= app.count; i++ {
		send(&app, client, h, i)
	}
}

func send(app *application, client *oidc.Client, h http.Header, i int) {
	label := fmt.Sprintf("request %d/%d", i, app.count)

	req, errReq := http.NewRequestWithContext(context.TODO(), app.targetMethod,
		app.targetURL, bytes.NewBufferString(app.targetBody))
	if errReq != nil {
		log.Fatalf("%s: request: %v", label, errReq)
	}

	maps.Copy(req.Header, h)

	var resp *http.Response
	var errDo error

	resp, errDo = client.Do(req)

	if errDo != nil {
		log.Fatalf("%s: do: %v", label, errDo)
	}
	defer resp.Body.Close()

	log.Printf("%s: status: %d", label, resp.StatusCode)

	body, errBody := io.ReadAll(resp.Body)
	if errBody != nil {
		log.Fatalf("%s: body: %v", label, errBody)
	}

	log.Printf("%s: body:", label)
	fmt.Println(string(body))

	if i < app.count && app.interval != 0 {
		log.Printf("%s: sleeping for interval=%v", label, app.interval)
		time.Sleep(app.interval)
	}
}
