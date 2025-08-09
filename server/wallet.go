package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/tinode/chat/server/store"
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

	// 0. get WalletToken
	cachedToken, tokenErr := store.PCache.Get(cacheKeyToken)
	if tokenErr != nil {
		return WalletToken{}, tokenErr
	}

	cachedExpiresStr, expiresErr := store.PCache.Get(cacheKeyForExpires)
	var expires time.Time
	if cachedExpiresStr != "" {
		expires, expiresErr = time.Parse(time.RFC822, cachedExpiresStr)
		if expiresErr != nil {
			// 解析失败，忽略或处理错误
			expires = time.Time{}
		}
	}
	walletToken := WalletToken{}
	walletToken.Expires = expires
	walletToken.Token = cachedToken

	return walletToken, nil
}
