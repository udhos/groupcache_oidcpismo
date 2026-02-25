package oidc

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/modernprogram/groupcache/v2"
	"github.com/udhos/oidcpismo/oidcpismo"
)

func loadKeys() (*rsa.PrivateKey, *rsa.PublicKey) {

	const (
		dir         = "testdata"
		privKeyFile = dir + "/key-priv.pem"
		pubKeyFile  = dir + "/key-pub.pem"
	)

	// private

	privKeyPem, errRead := os.ReadFile(privKeyFile)
	if errRead != nil {
		log.Fatalf("failed to read private key file: %s: %v",
			privKeyFile, errRead)
	}

	privKey, errParse := jwt.ParseRSAPrivateKeyFromPEM(privKeyPem)
	if errParse != nil {
		log.Fatalf("failed to parse private key: %v", errParse)
	}

	// public

	pubKeyPem, errReadPub := os.ReadFile(pubKeyFile)
	if errReadPub != nil {
		log.Fatalf("failed to read public key file: %s: %v",
			pubKeyFile, errReadPub)
	}

	pubKey, errParsePub := jwt.ParseRSAPublicKeyFromPEM(pubKeyPem)
	if errParsePub != nil {
		log.Fatalf("failed to parse public key: %v", errParsePub)
	}

	return privKey, pubKey
}

func TestOIDCPismo(t *testing.T) {

	expireIn := 60
	softExpire := 0

	tokenServerStat := serverStat{}
	serverStat := serverStat{}

	privKey, pubKey := loadKeys()

	ts := newTokenServer(&tokenServerStat, pubKey, expireIn)
	defer ts.Close()

	validToken := func(tok string) bool {
		err := validateTokenSignature(tok)
		if err != nil {
			t.Fatalf("invalid token signature: %v", err)
			return false
		}
		return true
	}

	srv := newServer(&serverStat, validToken)
	defer srv.Close()

	client := newClient(ts.URL, softExpire, privKey)

	h := map[string]string{
		"x-account-id": "account123",
	}

	// send 1

	{
		_, errSend := send(client, srv.URL, h)
		if errSend != nil {
			t.Errorf("send 1: %v", errSend)
		}
		if tokenServerStat.count != 1 {
			t.Errorf("send 1: unexpected token server access count: %d", tokenServerStat.count)
		}
		if serverStat.count != 1 {
			t.Errorf("send 1: unexpected server access count: %d", serverStat.count)
		}
	}

	// send 2

	_, errSend2 := send(client, srv.URL, h)
	if errSend2 != nil {
		t.Errorf("send 2: %v", errSend2)
	}
	if tokenServerStat.count != 1 {
		t.Errorf("send 2: unexpected token server access count: %d", tokenServerStat.count)
	}
	if serverStat.count != 2 {
		t.Errorf("send 2: unexpected server access count: %d", serverStat.count)
	}
}

func TestConcurrency(t *testing.T) {

	expireIn := 1
	softExpire := 0

	tokenServerStat := serverStat{}
	serverStat := serverStat{}

	privKey, pubKey := loadKeys()

	ts := newTokenServer(&tokenServerStat, pubKey, expireIn)
	defer ts.Close()

	validToken := func(tok string) bool {
		err := validateTokenSignature(tok)
		if err != nil {
			t.Fatalf("invalid token signature: %v", err)
			return false
		}
		return true
	}

	srv := newServer(&serverStat, validToken)
	defer srv.Close()

	client := newClient(ts.URL, softExpire, privKey)

	var wg sync.WaitGroup

	h := map[string]string{
		"x-account-id": "account123",
	}

	const N = 1 // FIXME TODO N=100

	for range N {
		wg.Go(func() {

			for range N {
				_, errSend := send(client, srv.URL, h)
				if errSend != nil {
					t.Errorf("send1: %v", errSend)
				}
			}

		})
	}

	wg.Wait()
}

// go test -count 1 -run TestExpiration ./...
func TestExpiration(t *testing.T) {

	expireIn := 1
	softExpire := -1 // disable soft expire

	tokenServerStat := serverStat{}
	serverStat := serverStat{}

	privKey, pubKey := loadKeys()

	ts := newTokenServer(&tokenServerStat, pubKey, expireIn)
	defer ts.Close()

	validToken := func(tok string) bool {
		err := validateTokenSignature(tok)
		if err != nil {
			t.Fatalf("invalid token signature: %v", err)
			return false
		}
		return true
	}

	srv := newServer(&serverStat, validToken)
	defer srv.Close()

	client := newClient(ts.URL, softExpire, privKey)

	h := map[string]string{
		"x-account-id": "account123",
	}

	// send 1

	{
		_, errSend := send(client, srv.URL, h)
		if errSend != nil {
			t.Errorf("send: %v", errSend)
		}
		if tokenServerStat.count != 1 {
			t.Errorf("unexpected token server access count: %d", tokenServerStat.count)
		}
		if serverStat.count != 1 {
			t.Errorf("unexpected server access count: %d", serverStat.count)
		}
	}

	time.Sleep(time.Second)

	// send 2

	{
		_, errSend2 := send(client, srv.URL, h)
		if errSend2 != nil {
			t.Errorf("send: %v", errSend2)
		}
		if tokenServerStat.count != 2 {
			t.Errorf("unexpected token server access count: %d", tokenServerStat.count)
		}
		if serverStat.count != 2 {
			t.Errorf("unexpected server access count: %d", serverStat.count)
		}
	}
}

func TestForcedExpiration(t *testing.T) {

	expireIn := 60
	softExpire := -1 // disable soft expire

	tokenServerStat := serverStat{}
	serverStat := serverStat{}

	privKey, pubKey := loadKeys()

	ts := newTokenServer(&tokenServerStat, pubKey, expireIn)
	defer ts.Close()

	var brokenToken bool

	validToken := func(tok string) bool {
		if brokenToken {
			return false
		}
		err := validateTokenSignature(tok)
		if err != nil {
			t.Fatalf("invalid token signature: %v", err)
			return false
		}
		return true
	}

	srv := newServer(&serverStat, validToken)
	defer srv.Close()

	client := newClient(ts.URL, softExpire, privKey)

	h := map[string]string{
		"x-account-id": "account123",
	}

	// send 1: get first token

	{
		_, errSend := send(client, srv.URL, h)
		if errSend != nil {
			t.Errorf("send: %v", errSend)
		}
		if tokenServerStat.count != 1 {
			t.Errorf("unexpected token server access count: %d", tokenServerStat.count)
		}
		if serverStat.count != 1 {
			t.Errorf("unexpected server access count: %d", serverStat.count)
		}
	}

	// send 2: get cached token

	{
		_, errSend2 := send(client, srv.URL, h)
		if errSend2 != nil {
			t.Errorf("send: %v", errSend2)
		}
		if tokenServerStat.count != 1 {
			t.Errorf("unexpected token server access count: %d", tokenServerStat.count)
		}
		if serverStat.count != 2 {
			t.Errorf("unexpected server access count: %d", serverStat.count)
		}
	}

	// send 3: break cached token

	brokenToken = true

	{
		result, errSend3 := send(client, srv.URL, h)
		if errSend3 == nil {
			t.Errorf("unexpected send success")
		}
		if result.status != 401 {
			t.Errorf("unexpected status: %d", result.status)
		}
		if tokenServerStat.count != 1 {
			t.Errorf("unexpected token server access count: %d", tokenServerStat.count)
		}
		if serverStat.count != 3 {
			t.Errorf("unexpected server access count: %d", serverStat.count)
		}
	}

	// send 4: fix token

	brokenToken = false

	{
		_, errSend3 := send(client, srv.URL, h)
		if errSend3 != nil {
			t.Errorf("send: %v", errSend3)
		}
		if tokenServerStat.count != 2 {
			t.Errorf("unexpected token server access count: %d", tokenServerStat.count)
		}
		if serverStat.count != 4 {
			t.Errorf("unexpected server access count: %d", serverStat.count)
		}
	}

}

func TestServerBrokenURL(t *testing.T) {

	expireIn := 0
	softExpire := 0

	tokenServerStat := serverStat{}
	serverStat := serverStat{}

	privKey, pubKey := loadKeys()

	ts := newTokenServer(&tokenServerStat, pubKey, expireIn)
	defer ts.Close()

	validToken := func(tok string) bool {
		err := validateTokenSignature(tok)
		if err != nil {
			t.Fatalf("invalid token signature: %v", err)
			return false
		}
		return true
	}

	srv := newServer(&serverStat, validToken)
	defer srv.Close()

	client := newClient(ts.URL, softExpire, privKey)

	h := map[string]string{
		"x-account-id": "account123",
	}

	// send

	{
		_, errSend := send(client, "broken-url", h)
		if errSend == nil {
			t.Errorf("unexpected success from broken server")
		}
		if tokenServerStat.count != 1 {
			t.Errorf("unexpected token server access count: %d", tokenServerStat.count)
		}
		if serverStat.count != 0 {
			t.Errorf("unexpected server access count: %d", serverStat.count)
		}
	}
}

func TestTokenServerBrokenURL(t *testing.T) {

	softExpire := 0

	serverStat := serverStat{}

	privKey, _ := loadKeys()

	validToken := func(tok string) bool {
		err := validateTokenSignature(tok)
		if err != nil {
			t.Fatalf("invalid token signature: %v", err)
			return false
		}
		return true
	}

	srv := newServer(&serverStat, validToken)
	defer srv.Close()

	client := newClient("broken-url", softExpire, privKey)

	h := map[string]string{
		"x-account-id": "account123",
	}

	// send 1

	_, errSend := send(client, srv.URL, h)
	if errSend == nil {
		t.Errorf("unexpected send success")
	}
}

func TestBrokenTokenServer(t *testing.T) {

	softExpire := 0

	tokenServerStat := serverStat{}
	serverStat := serverStat{}

	ts := newTokenServerBroken(&tokenServerStat)
	defer ts.Close()

	validToken := func(tok string) bool {
		err := validateTokenSignature(tok)
		if err != nil {
			t.Fatalf("invalid token signature: %v", err)
			return false
		}
		return true
	}

	srv := newServer(&serverStat, validToken)
	defer srv.Close()

	privKey, _ := loadKeys()

	client := newClient(ts.URL, softExpire, privKey)

	h := map[string]string{
		"x-account-id": "account123",
	}

	// send 1

	{
		_, errSend := send(client, srv.URL, h)
		if errSend == nil {
			t.Errorf("unexpected success with broken token server")
		}
		if tokenServerStat.count != 1 {
			t.Errorf("unexpected token server access count: %d", tokenServerStat.count)
		}
		if serverStat.count != 0 {
			t.Errorf("unexpected server access count: %d", serverStat.count)
		}
	}

	// send 2

	{
		_, errSend := send(client, srv.URL, h)
		if errSend == nil {
			t.Errorf("unexpected success with broken token server")
		}
		if tokenServerStat.count != 2 {
			t.Errorf("unexpected token server access count: %d", tokenServerStat.count)
		}
		if serverStat.count != 0 {
			t.Errorf("unexpected server access count: %d", serverStat.count)
		}
	}

}

func TestLockedTokenServer(t *testing.T) {

	expireIn := 60
	softExpire := 0

	tokenServerStat := serverStat{}
	serverStat := serverStat{}

	privKey, _ := loadKeys()

	wrongPubKey := &rsa.PublicKey{}

	ts := newTokenServer(&tokenServerStat, wrongPubKey, expireIn)
	defer ts.Close()

	validToken := func(tok string) bool {
		err := validateTokenSignature(tok)
		if err != nil {
			t.Fatalf("invalid token signature: %v", err)
			return false
		}
		return true
	}

	srv := newServer(&serverStat, validToken)
	defer srv.Close()

	client := newClient(ts.URL, softExpire, privKey)

	h := map[string]string{
		"x-account-id": "account123",
	}

	// send 1

	{
		_, errSend := send(client, srv.URL, h)
		if errSend == nil {
			t.Errorf("unexpected success with locked token server")
		}
		if tokenServerStat.count != 1 {
			t.Errorf("unexpected token server access count: %d", tokenServerStat.count)
		}
		if serverStat.count != 0 {
			t.Errorf("unexpected server access count: %d", serverStat.count)
		}
	}

	// send 2

	{
		_, errSend := send(client, srv.URL, h)
		if errSend == nil {
			t.Errorf("unexpected success with locked token server")
		}
		if tokenServerStat.count != 2 {
			t.Errorf("unexpected token server access count: %d", tokenServerStat.count)
		}
		if serverStat.count != 0 {
			t.Errorf("unexpected server access count: %d", serverStat.count)
		}
	}
}

type sendResult struct {
	body   string
	status int
}

func send(client *Client, serverURL string, h map[string]string) (sendResult, error) {

	var result sendResult

	req, errReq := http.NewRequestWithContext(context.TODO(), "GET", serverURL, nil)
	if errReq != nil {
		return result, fmt.Errorf("request: %v", errReq)
	}

	for k, v := range h {
		req.Header.Set(k, v)
	}

	resp, errDo := client.Do(req)

	if errDo != nil {
		return result, fmt.Errorf("do: %v", errDo)
	}
	defer resp.Body.Close()

	body, errBody := io.ReadAll(resp.Body)
	if errBody != nil {
		return result, fmt.Errorf("body: %v", errBody)
	}

	bodyStr := string(body)

	result.body = bodyStr
	result.status = resp.StatusCode

	if resp.StatusCode != 200 {
		return result, fmt.Errorf("bad status:%d body:%v", resp.StatusCode, bodyStr)
	}

	return result, nil
}

func formParam(r *http.Request, key string) string {
	v := r.Form[key]
	if v == nil {
		return ""
	}
	return v[0]
}

func newServer(stat *serverStat, validToken func(token string) bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stat.inc()
		h := r.Header.Get("Authorization")
		t := strings.TrimPrefix(h, "Bearer ")
		if !validToken(t) {
			httpJSON(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		httpJSON(w, `{"message":"ok"}`, http.StatusOK)
	}))
}

// httpJSON replies to the request with the specified error message and HTTP code.
// It does not otherwise end the request; the caller should ensure no further
// writes are done to w.
// The message should be JSON.
func httpJSON(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	fmt.Fprintln(w, message)
}

type serverStat struct {
	count int
	mutex sync.Mutex
}

func (stat *serverStat) inc() {
	stat.mutex.Lock()
	stat.count++
	stat.mutex.Unlock()
}

var sampleSecretKey = []byte("mysecretkey")

func newToken(exp int) (string, error) {
	accessToken := jwt.New(jwt.SigningMethodHS256)
	claims := accessToken.Claims.(jwt.MapClaims)
	now := time.Now()
	claims["iat"] = now.Unix()
	if exp > 0 {
		claims["exp"] = now.Add(time.Duration(exp) * time.Second).Unix()
	}

	str, errSign := accessToken.SignedString(sampleSecretKey)
	if errSign != nil {
		return "", errSign
	}
	return str, nil
}

func validateTokenSignature(token string) error {
	tk, errParse := jwt.Parse(token, func(_ *jwt.Token) (any, error) {
		return sampleSecretKey, nil
	})
	if errParse != nil {
		return fmt.Errorf("token parse error: %v", errParse)
	}
	if !tk.Valid {
		return fmt.Errorf("invalid token")
	}
	return nil
}

func newTokenServer(serverInfo *serverStat, pubKey *rsa.PublicKey, expireIn int) *httptest.Server {

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		serverInfo.inc()

		// read body

		body, errRead := io.ReadAll(r.Body)
		if errRead != nil {
			http.Error(w, errRead.Error(), http.StatusInternalServerError)
			return
		}

		// parse request

		var tokReq oidcpismo.Request
		errUnmarshal := json.Unmarshal(body, &tokReq)
		if errUnmarshal != nil {
			http.Error(w, errUnmarshal.Error(), http.StatusBadRequest)
			return
		}

		// parse jwt token

		tk, errParse := jwt.Parse(tokReq.Token, func(_ *jwt.Token) (any, error) {
			return pubKey, nil
		})
		if errParse != nil {
			http.Error(w, fmt.Sprintf("token parse error: %v", errParse),
				http.StatusBadRequest)
			return
		}

		if !tk.Valid {
			http.Error(w, "invalid token", http.StatusBadRequest)
			return
		}

		exp, errExp := tk.Claims.GetExpirationTime()
		if errExp != nil {
			http.Error(w, fmt.Sprintf("token expiration time error: %v", errExp),
				http.StatusBadRequest)
			return
		}

		// calculate remaining time until token expiration

		now := time.Now()
		if exp.Before(now) {
			http.Error(w, "token expired", http.StatusUnauthorized)
			return
		}

		remaining := exp.Sub(now)
		log.Printf("%s %s %s - token valid - remaining time until expiration: %v",
			r.RemoteAddr, r.Method, r.RequestURI, remaining)

		// create access token

		accessToken, errToken := newToken(int(remaining.Seconds()))
		if errToken != nil {
			http.Error(w, errToken.Error(), http.StatusInternalServerError)
			return
		}

		// reply with access token

		var resp oidcpismo.Response
		resp.Token = accessToken
		resp.ExpiresIn = fmt.Sprint(expireIn)
		resp.RefreshToken = "some-refresh-token"
		data, err := json.Marshal(&resp)
		if err != nil {
			http.Error(w, fmt.Sprintf("response marshal error: %v", err),
				http.StatusInternalServerError)
			return
		}

		httpJSON(w, string(data), http.StatusCreated)
	}))
}

func newTokenServerBroken(serverInfo *serverStat) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ /*r*/ *http.Request) {
		serverInfo.inc()
		httpJSON(w, "broken-token", http.StatusOK)
	}))
}

func newClient(tokenURL string, softExpire int,
	privKey *rsa.PrivateKey) *Client {

	options := oidcpismo.Options{
		TokenURL: tokenURL,
		Client:   http.DefaultClient,
		PrivKey:  privKey,

		//
		// These claims are non-standard claims required by Pismo.
		// See: https://developers.pismo.io/pismo-docs/docs/authentication-with-openid#generate-your-jwt
		//
		TenantID: "tenant-id",
		UID:      "account-id",
		Pismo: map[string]any{
			"group": "pismo-v1:some-samplegroup:rw",
		},
		// Only CustomClaims is optional, you can omit it if you don't need to add custom claims.
		CustomClaims: map[string]any{
			"custom1":     "someValue",
			"userexample": "user@user.com",
		},

		//
		// Registered claims
		//
		Issuer:   "issuer",
		Subject:  "subject",
		Audience: "audience",
		Expire:   2 * time.Minute,
	}

	opt := Options{
		Options:             options,
		SoftExpireInSeconds: softExpire,
		GroupcacheWorkspace: groupcache.NewWorkspace(),
		Debug:               true,
	}

	client := New(opt)

	return client
}
