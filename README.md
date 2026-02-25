[![license](http://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/udhos/groupcache_oidcpismo/blob/main/LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/udhos/groupcache_oidcpismo)](https://goreportcard.com/report/github.com/udhos/groupcache_oidcpismo)
[![Go Reference](https://pkg.go.dev/badge/github.com/udhos/groupcache_oidcpismo.svg)](https://pkg.go.dev/github.com/udhos/groupcache_oidcpismo)

# groupcache_oidcpismo

https://github.com/udhos/groupcache_oidcpismo implements the OIDC flow for Pismo while cacheing tokens with distributed cache [groupcache](https://github.com/modernprogram/groupcache).

# Synopsis

Create an HTTP client that can automatically obtain and refresh OIDC tokens for Pismo, while managing cached tokens in distributed cache groupcache.

NOTE: Do not forget to add the required header `x-account-id`.

```golang
privKeyPem, errRead := os.ReadFile("key-priv.pem")

privKey, errParse := jwt.ParseRSAPrivateKeyFromPEM(privKeyPem)

opt := oidcpismo.Options{
    TokenURL: "https://sandbox.pismolabs.io/passport/v1/oauth2/token",
    Client:   http.DefaultClient,
    PrivKey:  privKey,

    TenantID:     "tenant-id",
    Pismo:        map[string]any{
        "group": "pismo-v1:some-samplegroup:rw",
    },
    CustomClaims: map[string]any{
        "custom1":     "someValue",
        "userexample": "user@user.com",
    },
    Issuer:   "issuer",
    Subject:  "subject",
    Audience: "audience",
    Expire:   time.Hour,
}

options := oidc.Options{
    Options:             opt,
    GroupcacheWorkspace: groupcacheWorkspace,
}

client := oidc.New(options)

req, errReq := http.NewRequestWithContext(context.TODO(), "GET",
    "http://example.com", nil)

req.Header.Add("x-account-id", "some-account-id")

resp, errDo = client.Do(req)
```

# Example

See [cmd/groupcache-oidcpismo-client-example/main.go](cmd/groupcache-oidcpismo-client-example/main.go) for a complete example.

# Testing

Start the token server `oidcpismo-server` from project https://github.com/udhos/oidcpismo:

```bash
oidcpismo-server
```

Run the example client:

```bash
groupcache-oidcpismo-client-example
```
