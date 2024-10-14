package main

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

// Users must configure the const var to their auth settings.
// Host "https://your.senhasegurahost.com"
// PKPath File path to the private key to decrypt sensitive data
// ClientId for A2A API Oauth2.0 authentication
// ClientSecret for A2A API Oauth2.0 authentication
const (
	Host         = ""
	PkPath       = ""
	ClientId     = ""
	ClientSecret = ""
)

var token string

type Token struct {
	Token_type string `json:"token_type"`
	Expires    int    `json:"expires_in"`
	Token      string `json:"access_token"`
}

func setToken(token Token) string {
	return token.Token
}

type Response struct {
	Status    int    `json:"status"`
	Mensagem  string `json:"mensagem"`
	Erro      bool   `json:"erro"`
	Detail    string `json:"detail"`
	CodErro   int    `json:"cod_erro"`
	Message   string `json:"message"`
	Error     bool   `json:"error"`
	ErrorCode int    `json:"error_code"`
}

type Credential struct {
	ID                  string `json:"id"`
	Tag                 string `json:"tag"`
	Username            string `json:"username"`
	Password            string `json:"password"`
	Content             string `json:"content"`
	Hostname            string `json:"hostname"`
	ParentCredential    string `json:"parent_credential"`
	ParentCredentialCod string `json:"parent_credential_cod"`
	Additional          string `json:"additional"`
	Domain              string `json:"domain"`
	IP                  string `json:"ip"`
	Port                string `json:"port"`
	Model               string `json:"model"`
	ExpirationTime      string `json:"expiration_time"`
}

type Exception struct {
	Message string `json:"message"`
}

type Data struct {
	Response   Response   `json:"response"`
	Credential Credential `json:"credential"`
	Exception  Exception  `json:"exception"`
}

func post(url string, data *strings.Reader) (*http.Request, error) {
	url = Host + url
	return http.NewRequest("POST", url, data)
}

func get(url string, data *strings.Reader) (*http.Request, error) {
	url = Host + url
	return http.NewRequest("GET", url, data)
}

// Retrieve Bearer Token for Oauth2.0 Authenticaton
func getToken() (string, error) {
	var token Token
	request, err := post("/iso/oauth2/token", strings.NewReader("grant_type=client_credentials"))
	if err != nil {
		return "", err
	}
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	auth := base64.StdEncoding.EncodeToString([]byte(ClientId + ":" + ClientSecret))
	request.Header.Add("Authorization", "Basic "+auth)

	client := &http.Client{}
	res, err := client.Do(request)
	if err != nil {
		return "", err
	}

	defer res.Body.Close()
	//TODO: ioutl.ReadAll is deprecated
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	err = json.Unmarshal(body, &token)
	if err != nil {
		return "", err
	}

	return setToken(token), nil
}

// Get Credential for specific account on specific device
func getCredential(credentialID int) (*Data, error) {
	var data Data

	request, err := get(fmt.Sprintf("/iso/pam/credential/%d", credentialID), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("Authorization", "Bearer "+token)

	client := &http.Client{}
	res, err := client.Do(request)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()
	//TODO: ioutl.ReadAll is deprecated
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(body, &data)
	if err != nil {
		return nil, err
	}

	return &data, nil
}

// Senhasegura Allows enablement of sensitive data encryption. If enabled, we'll need to decrypt the data with a private key
func decryptPassword(encrypted string, privateKeyPath string) (string, error) {
	privateKeyData, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		return "", err
	}

	block, _ := pem.Decode(privateKeyData)
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}

	fmt.Println("privateKey : ", privateKey)

	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return "", err
	}

	cipherText, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}

	plainText, err := rsa.DecryptOAEP(sha1.New(), nil, rsaPrivateKey, cipherText, nil)
	if err != nil {
		return "", err
	}

	return string(plainText), err
}

// Used to detect encrypted data enablement
func isBase64(s string) bool {
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}

func main() {
	var request *Data

	token, err := getToken()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Token: " + token)

	var credentialID int
	fmt.Print("Enter Credential ID: ")
	_, err = fmt.Scan(&credentialID)
	if err != nil {
		log.Fatal(err)
	}

	request, err = getCredential(credentialID)

	if request.Response.Status != 200 {
		log.Fatalf("Failed to gather credential. Error: %s\n", request.Response.Message)
	}

	password := request.Credential.Password
	username := request.Credential.Username

	if isBase64(password) {
		fmt.Println("Password encryption enabled. Attempting to decrypt password.")

		plainText, err := decryptPassword(password, PkPath)

		if err != nil {
			log.Fatal(err)
		}

		password = plainText
	}

	fmt.Println("Username:", username, "\nPassword", password)
}
