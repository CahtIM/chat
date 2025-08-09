package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/cahtio/chat/server/store"
)

const WalletHost = "http://172.0.0.1:3239"
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

		// 3. update WalletToken
		walletToken = WalletToken{
			Token:   newToken,
			Expires: time.Now().Add(7 * 24 * time.Hour),
		}

		// save new WalletToken
		store.PCache.Upsert((WalletTokenCacheKey + uid), walletToken.Token, true)
		store.PCache.Upsert((WalletTokenExpiresCacheKey + uid), walletToken.Expires.Format(time.RFC822), true)
	}

	return walletToken, nil
}

func getBServiceToken(uid string) (string, error) {

	url := fmt.Sprintf(WalletHost, WalletTokenPath)

	// send request to B service
	// body
	requestBody, err := json.Marshal(map[string]string{
		"uid": uid,
	})
	if err != nil {
		return "", fmt.Errorf("error creating request body: %v", err)
	}

	// send request
	req, err := http.NewRequest("GET", url, bytes.NewBuffer(requestBody))
	if err != nil {
		return "", fmt.Errorf("error creating request: %v", err)
	}

	// add header
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", WalletAuthorization)

	// send
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error sending request: %v", err)
	}
	defer resp.Body.Close()

	// read response
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

func getWalletTokenFromCache(uid string) (WalletToken, error) {
	cacheKeyToken := WalletTokenCacheKey + uid
	cacheKeyForExpires := WalletTokenExpiresCacheKey + uid

	// 检查 store.PCache 是否为 nil
	if store.PCache == nil {
		return WalletToken{}, fmt.Errorf("cache is not initialized")
	}

	// 获取 token
	cachedToken, tokenErr := store.PCache.Get(cacheKeyToken)
	if tokenErr != nil {
		return WalletToken{}, fmt.Errorf("error getting token from cache: %v", tokenErr)
	}

	// 获取过期时间
	cachedExpiresStr, expiresErr := store.PCache.Get(cacheKeyForExpires)
	if expiresErr != nil {
		return WalletToken{}, fmt.Errorf("error getting expiration time from cache: %v", expiresErr)
	}

	var expires time.Time
	if cachedExpiresStr != "" {
		expires, expiresErr = time.Parse(time.RFC822, cachedExpiresStr)
		if expiresErr != nil {
			// 解析失败，使用零值时间
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
