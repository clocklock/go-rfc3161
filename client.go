package rfc3161

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"io/ioutil"
	"net/http"
)

// Errors
var (
	ErrRequestFailed = errors.New("rfc3161: client: Request failed")
)

// Client handles requests to an HTTP or websocket time-stamp-service
// You may override the underlying http client used by setting the HTTPClient field
type Client struct {
	HTTPClient *http.Client
	URL        string
}

// NewClient creates a new rfc3161.Client given a URL.
func NewClient(url string) *Client {
	client := new(Client)
	client.HTTPClient = http.DefaultClient
	client.URL = url
	return client
}

// Do a time stamp request and get back the Time Stamp Response.
// This will not verify the response. It is the caller's responsibility
// to call resp.Verify() on the returned TimeStampResp.
func (client *Client) Do(tsq *TimeStampReq) (*TimeStampResp, error) {
	der, err := asn1.Marshal(*tsq)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", client.URL, bytes.NewBuffer(der))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/timestamp-query")

	resp, err := client.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	tsr := new(TimeStampResp)
	rest, err := asn1.Unmarshal(body, tsr)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, ErrUnrecognizedData
	}

	if tsr.Status.Status.IsError() {
		return tsr, &tsr.Status
	}
	return tsr, nil
}
