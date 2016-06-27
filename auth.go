package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

const (
	HTTP  = "http"
	HTTPS = "https"
)

type TokenRequest struct {
	User     *string
	Password *string
	Realm    *string
	Scopes   []string
}

type Authentication struct {
	url string
}

func NewAuthentication(url string) *Authentication {
	return &Authentication{url: url}
}

func NewTokenRequest(user string, password string, scopes ...string) TokenRequest {
	return TokenRequest{User: &user, Password: &password, Scopes: scopes}
}

func (auth *Authentication) RequestToken(tokReq TokenRequest) (*string, error) {

	url, err := buildTokenUrl(auth.url, tokReq)
	token, err := requestTokenInfo(url, tokReq)
	if err != nil {
		return nil, err
	}

	if val, exists := token["access_token"]; exists {
		access_token := val.(string)
		return &access_token, nil
	}
	return nil, fmt.Errorf("The access token couldn't be aquired")
}

func requestTokenInfo(url *url.URL, tokReq TokenRequest) (map[string]interface{}, error) {

	client := createClient()

	req, err := http.NewRequest(http.MethodGet, url.String(), nil)
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(*tokReq.User, *tokReq.Password)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Authentication failed, server has returned %d status code", resp.StatusCode)
	}
	return decodeMap(resp.Body)
}

func buildTokenUrl(rawurl string, req TokenRequest) (*url.URL, error) {

	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}
	u.Scheme = HTTPS
	q := u.Query()
	q.Add("json", "true")
	if req.Realm != nil {
		q.Add("realm", *req.Realm)
	}
	if req.Scopes != nil {
		for _, scope := range req.Scopes {
			q.Add("scope", scope)
		}
	}
	u.RawQuery = q.Encode()
	return u, nil
}

func decodeMap(body io.ReadCloser) (map[string]interface{}, error) {
	var result map[string]interface{}
	decoder := json.NewDecoder(body)
	if err := decoder.Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

func createClient() *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{Transport: transport}
}
