// Package oidc helps with OIDC flow for Pismo.
package oidc

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/modernprogram/groupcache/v2"
	"github.com/udhos/oidcpismo/oidcpismo"
)

// DefaultGroupCacheSizeBytes is default group cache size when unspecified.
const DefaultGroupCacheSizeBytes = 10_000_000

// Options define client options.
type Options struct {
	// Options for package oidcpismo to retrieve access token.
	Options oidcpismo.Options

	// SoftExpireInSeconds specifies how early before hard expiration the
	// token should be considered expired to trigger renewal. This
	// prevents from using an expired token due to clock
	// differences.
	//
	// 0 defaults to 10 seconds. Set to -1 to no soft expire.
	//
	// Example: consider expire_in = 30 seconds and soft expire = 10 seconds.
	// The token will hard expire after 30 seconds, but we will consider it
	// expired after (30-10) = 20 seconds, in order to attempt renewal before
	// hard expiration.
	//
	SoftExpireInSeconds int

	// GroupcacheWorkspace is required groupcache workspace.
	GroupcacheWorkspace *groupcache.Workspace

	// GroupcacheName gives a unique cache name. If unspecified, defaults to oidcpismo.
	GroupcacheName string

	// GroupcacheSizeBytes limits the cache size. If unspecified, defaults to 10MB.
	GroupcacheSizeBytes int64

	// Logf provides logging function, if undefined defaults to log.Printf
	Logf func(format string, v ...any)

	// Debug enables debug logging.
	Debug bool

	// DisablePurgeExpired disables removing all expired items when the oldest item is removed.
	DisablePurgeExpired bool

	// ExpiredKeysEvictionInterval sets interval for periodic eviction of expired keys.
	// If unset, defaults to 30-minute period.
	// Set to -1 to disable periodic eviction of expired keys.
	ExpiredKeysEvictionInterval time.Duration

	// GroupcacheMainCacheWeight defaults to 8 if unspecified.
	GroupcacheMainCacheWeight int64

	// GroupcacheHotCacheWeight defaults to 1 if unspecified.
	GroupcacheHotCacheWeight int64

	// IsBadTokenStatus checks if the server response status is bad token.
	// If undefined, defaults to DefaultBadTokenStatusFunc that just checks for 401.
	IsBadTokenStatus func(status int) bool

	// GetPathValueFromRequest gets a value from the request path.
	// If undefined, defaults to DefaultGetPathValueFromRequest that just calls req.PathValue.
	GetPathValueFromRequest func(req *http.Request, key string) string
}

// DefaultGetPathValueFromRequest is used as default when option GetPathValueFromRequest
// is left undefined.
func DefaultGetPathValueFromRequest(req *http.Request, key string) string {
	return req.PathValue(key)
}

// DefaultBadTokenStatusFunc is used as default when option IsBadTokenStatus is left undefined.
// DefaultBadTokenStatusFunc reports if status is 401.
func DefaultBadTokenStatusFunc(status int) bool {
	return status == 401
}

// Client is an HTTP client that can automatically obtain and refresh OIDC tokens
// for Pismo, while managing cached tokens in distributed cache groupcache.
type Client struct {
	options Options
	group   *groupcache.Group
}

// New creates a Client.
func New(options Options) *Client {
	if options.GroupcacheWorkspace == nil {
		panic("groupcache workspace is nil")
	}

	switch options.SoftExpireInSeconds {
	case 0:
		options.SoftExpireInSeconds = 10
	case -1:
		options.SoftExpireInSeconds = 0
	}

	if options.Logf == nil {
		options.Logf = log.Printf
	}

	if options.IsBadTokenStatus == nil {
		options.IsBadTokenStatus = DefaultBadTokenStatusFunc
	}

	if options.GetPathValueFromRequest == nil {
		options.GetPathValueFromRequest = DefaultGetPathValueFromRequest
	}

	c := &Client{
		options: options,
	}

	cacheSizeBytes := options.GroupcacheSizeBytes
	if cacheSizeBytes == 0 {
		cacheSizeBytes = DefaultGroupCacheSizeBytes
	}

	cacheName := options.GroupcacheName
	if cacheName == "" {
		cacheName = "oidcpismo"
	}

	o := groupcache.Options{
		Workspace:                   options.GroupcacheWorkspace,
		Name:                        cacheName,
		PurgeExpired:                !options.DisablePurgeExpired,
		ExpiredKeysEvictionInterval: options.ExpiredKeysEvictionInterval,
		CacheBytesLimit:             cacheSizeBytes,
		Getter: groupcache.GetterFunc(
			func(ctx context.Context, accountID string, dest groupcache.Sink,
				_ *groupcache.Info) error {

				ti, errTok := c.fetchToken(ctx, accountID)
				if errTok != nil {
					return errTok
				}

				softExpire := time.Duration(options.SoftExpireInSeconds) * time.Second

				expire := time.Now().Add(ti.expire - softExpire)

				return dest.SetString(ti.accessToken, expire)
			}),
		MainCacheWeight: options.GroupcacheMainCacheWeight,
		HotCacheWeight:  options.GroupcacheHotCacheWeight,
	}

	group := groupcache.NewGroupWithWorkspace(o)

	c.group = group

	return c
}

func (c *Client) errorf(format string, v ...any) {
	c.options.Logf("ERROR: "+format, v...)
}

func (c *Client) debugf(format string, v ...any) {
	if c.options.Debug {
		c.options.Logf("DEBUG: "+format, v...)
	}
}

func (c *Client) getAccountID(req *http.Request) (string, string) {
	if accountID := c.options.GetPathValueFromRequest(req, "accountId"); accountID != "" {
		return accountID, "path"
	}

	if accountID := req.Header.Get("X-Account-ID"); accountID != "" {
		return accountID, "header"
	}

	return "", "not-found"
}

// Do sends an HTTP request and returns an HTTP response.
// The actual HTTP Client provided in the Options is used to make the requests
// and also to retrieve the required access token.
// Do retrieves the token and renews it as necessary for making the request.
func (c *Client) Do(req *http.Request) (*http.Response, error) {

	// get account id from request
	accountID, accountIDSource := c.getAccountID(req)
	c.debugf("account_id=%q accoud_id_source=%q", accountID, accountIDSource)

	// get token from cache, renewing it if necessary
	ctx := req.Context()
	var accessToken string
	if errToken := c.group.Get(ctx, accountID,
		groupcache.StringSink(&accessToken), nil); errToken != nil {
		return nil, errToken
	}

	// send request with header Authorization: Bearer <access_token>
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	resp, errResp := c.options.Options.Client.Do(req)
	if errResp != nil {
		return nil, errResp
	}

	if c.options.IsBadTokenStatus(resp.StatusCode) {
		//
		// the server refused our token, so we expire it in order to
		// renew it at the next invokation.
		//
		if errRemove := c.group.Remove(ctx, accountID); errRemove != nil {
			c.errorf("cache remove error: %v", errRemove)
		}
	}

	return resp, nil
}

// fetchToken actually retrieves new access token from token server.
func (c *Client) fetchToken(ctx context.Context,
	accountID string) (ti tokenInfo, err error) {

	options := c.options.Options

	options.UID = accountID

	resp, errTok := oidcpismo.GetAccessToken(ctx, options)
	if errTok != nil {
		err = errTok
		return
	}

	exp, errConv := strconv.Atoi(resp.ExpiresIn)
	if errConv != nil {
		err = errConv
		return
	}

	ti.accessToken = resp.Token
	ti.expire = time.Duration(exp) * time.Second

	return
}

type tokenInfo struct {
	accessToken string
	expire      time.Duration
}
