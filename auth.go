package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"bufio"
	"os"
	"syscall"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	HTTPS = "https"
	ACCESS_TOKEN = "access_token"
)

type TokenRequest struct {
	User     string
	Password string
	Realm    *string
	Scopes   []string
}

type Authentication interface {
	Enrich(*http.Request)
}

type Authenticator interface {
	Authenticate() (Authentication, error)
}

type BearerTokenAuthentication struct {
	token *string
}

func (auth BearerTokenAuthentication) Enrich(req *http.Request) {
	if auth.token != nil {
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", auth.token))
	}
}

type OAuth2Authenticator struct {
	url string
}

func NewOAuth2Authenticator(url string) Authenticator {
	return &OAuth2Authenticator{url: url}
}

func (auth *OAuth2Authenticator) Authenticate() (Authentication, error) {
	// TODO implement credentials

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter user name: ")
	user, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	fmt.Print("Enter password: ")
	password, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return nil, err
	}
	fmt.Println()

	req := TokenRequest{User: user, Password: string(password), Scopes: []string{"uid"}}
	token, err := auth.RequestToken(req)
	if err != nil {
		return nil, err
	}
	return &BearerTokenAuthentication{token: token}, nil
}

func (auth *OAuth2Authenticator) RequestToken(tokReq TokenRequest) (*string, error) {

	url, err := buildTokenUrl(auth.url, tokReq)
	if err != nil {
		return nil, err
	}
	token, err := requestTokenInfo(url, tokReq)
	if err != nil {
		return nil, err
	}

	if val, exists := token[ACCESS_TOKEN]; exists {
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

	req.SetBasicAuth(tokReq.User, tokReq.Password)
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
