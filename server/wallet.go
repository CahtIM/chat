package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/cahtio/chat/server/store"
)

const WalletHost = "http://127.0.0.1:9753"
const WalletTokenPath = "/app/authToken"
const WalletGetaddressPath = "/balance/rechargeInfo/"
const WalletAuthorization = "123456"
const WalletTokenCacheKey = "WalletToken_"
const WalletTokenExpiresCacheKey = "WalletTokenExpires_"

type WalletToken struct {
	Token   string    `json:"token"`
	Expires time.Time `json:"expires"`
}

type BServiceResponse struct {
	Msg    string `json:"msg"`
	Data   string `json:"data"`
	Status string `json:"status"`
	Code   int    `json:"code"`
}

func getWalletToken(uid string) (WalletToken, error) {

	walletToken, err := getWalletTokenFromCache(uid)

	// 1. check
	if err != nil || time.Now().After(walletToken.Expires) {
		// 2. network walletToken
		newToken, err := getBServiceToken(uid)
		if err != nil {
			return WalletToken{}, err
		}
		// 3. get expTime from JWT
		expTime, err := parseJWTExp(newToken)
		if err != nil {
			// defaut 1 day
			expTime = time.Now().Add(1 * 24 * time.Hour)
		}
		// 4. update WalletToken
		walletToken = WalletToken{
			Token:   newToken,
			Expires: expTime,
		}

		// save new WalletToken
		store.PCache.Upsert((WalletTokenCacheKey + uid), walletToken.Token, true)
		store.PCache.Upsert((WalletTokenExpiresCacheKey + uid), walletToken.Expires.Format(time.RFC822), true)
	}

	return walletToken, nil
}

func getBServiceToken(uid string) (string, error) {
	//  url ，
	url := WalletHost + WalletTokenPath

	// send body
	requestBody, err := json.Marshal(map[string]string{
		"uid": uid,
	})
	if err != nil {
		return "", fmt.Errorf("error creating request body: %v", err)
	}

	// POST
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(requestBody))
	if err != nil {
		return "", fmt.Errorf("error creating request: %v", err)
	}

	// add Header
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", WalletAuthorization)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error sending request: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response body: %v", err)
	}

	var bResp BServiceResponse
	err = json.Unmarshal(body, &bResp)
	if err != nil {
		return "", fmt.Errorf("error unmarshaling response: %v", err)
	}

	if bResp.Status != "ok" || bResp.Code != 0 {
		return "", fmt.Errorf("B service error: %s", bResp.Msg)
	}

	return bResp.Data, nil
}

// Decode JWT , return exp
func parseJWTExp(token string) (time.Time, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return time.Time{}, fmt.Errorf("invalid JWT token format")
	}

	payloadSegment := parts[1]
	// JWT payload is base64url encoded, need to pad before decoding
	padding := 4 - len(payloadSegment)%4
	if padding < 4 {
		payloadSegment += strings.Repeat("=", padding)
	}

	payloadBytes, err := base64.URLEncoding.DecodeString(payloadSegment)
	if err != nil {
		return time.Time{}, fmt.Errorf("base64 decode error: %v", err)
	}

	var payloadMap map[string]interface{}
	err = json.Unmarshal(payloadBytes, &payloadMap)
	if err != nil {
		return time.Time{}, fmt.Errorf("json unmarshal error: %v", err)
	}

	expFloat, ok := payloadMap["exp"].(float64)
	if !ok {
		return time.Time{}, fmt.Errorf("exp field not found or invalid")
	}

	expTime := time.Unix(int64(expFloat), 0)
	return expTime, nil
}

func getWalletTokenFromCache(uid string) (WalletToken, error) {
	cacheKeyToken := WalletTokenCacheKey + uid
	cacheKeyForExpires := WalletTokenExpiresCacheKey + uid

	// check store.PCache is nil
	if store.PCache == nil {
		return WalletToken{}, fmt.Errorf("cache is not initialized")
	}

	// get token
	cachedToken, tokenErr := store.PCache.Get(cacheKeyToken)
	if tokenErr != nil {
		return WalletToken{}, fmt.Errorf("error getting token from cache: %v", tokenErr)
	}

	// get expires
	cachedExpiresStr, expiresErr := store.PCache.Get(cacheKeyForExpires)
	if expiresErr != nil {
		return WalletToken{}, fmt.Errorf("error getting expiration time from cache: %v", expiresErr)
	}

	var expires time.Time
	if cachedExpiresStr != "" {
		expires, expiresErr = time.Parse(time.RFC822, cachedExpiresStr)
		if expiresErr != nil {
			// use zero time
			expires = time.Time{}
		}
	}

	walletToken := WalletToken{
		Token:   cachedToken,
		Expires: expires,
	}

	return walletToken, nil
}

// const realName = "code"

// func init() {
// 	store.RegisterAuthScheme(realName, &authenticator{})
// }
