package goname

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"os"
)

// GoName API controller
type GoName struct {
	client        *http.Client
	username      string
	apikey        string
	baseURL       string
	session_token string
}

// Result standard API success response
type Result struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// DomainRecord DNS record information
type DomainRecord struct {
	RecordID   int    `json:"record_id"`
	Name       string `json:"name"`
	HostName   string `json:"hostname"`
	Type       string `json:"type"`
	Content    string `json:"content"`
	TTL        int    `json:"ttl"`
	CreateDate string `json:"create_date"`
	Priority   string `json:"priority,omitempty"`
}

// DNSChangeResponse response data from a DNS change
type DNSChangeResponse struct {
	Result Result `json:"result"`
	DomainRecord
}

// LoginData response data from logging in
type LoginData struct {
	Result       Result `json:"result"`
	SessionToken string `json:"session_token"`
}

// ListDomainsResponse Data returned from dns list
type ListDomainsResponse struct {
	Result  Result         `json:"result"`
	Records []DomainRecord `json:"records"`
}

// AccountResponse standard account response struct
type AccountResponse struct {
	Result        Result        `json:"result"`
	Username      string        `json:"username"`
	CreateDate    string        `json:"create_date"`
	DomainCount   string        `json:"domain_count"`
	AccountCredit string        `json:"account_credit"`
	Contacts      []interface{} `json:"contacts"`
}

// DeleteDNSRecord deletes a record on a domain
func (gn *GoName) DeleteDNSRecord(domainName string, record map[string]string) error {
	creatednsData := new(DNSChangeResponse)

	jsondata, err := json.Marshal(record)
	if err != nil {
		return err
	}
	err = gn.post(fmt.Sprintf("/api/dns/create/%s", domainName), jsondata, creatednsData)
	return err
}

// CreateDNSRecord creates a record on a domain
func (gn *GoName) CreateDNSRecord(domainName string, record DomainRecord) (*DomainRecord, error) {
	creatednsData := new(DNSChangeResponse)

	jsondata, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	err = gn.post(fmt.Sprintf("/api/dns/create/%s", domainName), jsondata, creatednsData)
	return &creatednsData.DomainRecord, err
}

// ListDNSRecords retrives records created on supplied domain name
func (gn *GoName) ListDNSRecords(domainName string) ([]DomainRecord, error) {
	dnsrespData := new(ListDomainsResponse)

	err := gn.get(fmt.Sprintf("/api/dns/list/%s", domainName), dnsrespData)
	if err != nil {
		return dnsrespData.Records, err
	}

	return dnsrespData.Records, err
}

// Account retunrs the associated Name.com account information
func (gn *GoName) Account() (AccountResponse, error) {
	accData := AccountResponse{}

	err := gn.get("/api/account/get", &accData)
	if err != nil {
		return accData, err
	}

	fmt.Println(accData)

	return accData, err
}

// Login logs the name.com API session in and sets the session token
func (gn *GoName) Login() error {
	jsonStr := []byte(fmt.Sprintf(`{"username":"%s","api_token":"%s"}`, gn.username, gn.apikey))

	loginData := new(LoginData)
	err := gn.post("/api/login", jsonStr, loginData)
	if err != nil {
		fmt.Println(err)
		return err
	}

	gn.session_token = loginData.SessionToken

	return err
}

// Logout logs the name.com API session out
func (gn *GoName) Logout() error {
	res := new(Result)
	err := gn.get("/api/logout", res)
	return err
}

func (gn *GoName) post(url string, jsonStr []byte, data interface{}) error {
	req, err := http.NewRequest("POST", gn.baseURL+url, bytes.NewBuffer(jsonStr))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	return gn.request(req, data)
}

func (gn *GoName) request(req *http.Request, data interface{}) error {
	req.Header.Set("Api-Session-Token", gn.session_token)

	resp, err := gn.client.Do(req)
	defer resp.Body.Close()

	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return errors.New(fmt.Sprintf("Request error name.com: %s", resp.Status))
	}

	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(data)

	return err
}

func (gn *GoName) get(url string, data interface{}) error {
	req, err := http.NewRequest("GET", gn.baseURL+url, nil)
	if err != nil {
		return err
	}

	return gn.request(req, data)
}

// New Creates a new Name.com API controller
func New(username, apikey string) *GoName {
	cookieJar, _ := cookiejar.New(nil)

	var baseURL string
	if os.Getenv("NAMECOM_DEV") != "" {
		baseURL = "https://api.dev.name.com"
	} else {
		baseURL = "https://api.name.com"
	}

	client := &http.Client{
		Jar: cookieJar,
	}

	gn := &GoName{
		client:   client,
		username: username,
		apikey:   apikey,
		baseURL:  baseURL,
	}

	return gn
}
