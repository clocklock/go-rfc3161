package rfc3161

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"io/ioutil"
	"net/http"
)

var ErrUnrecognizedData = errors.New("rfc3161: client: Got unrecognized data in the TSR")

type Client struct {
	HttpClient *http.Client
	Endpoint   string
}

func NewClient(endpoint string) *Client {
	client := new(Client)
	client.HttpClient = http.DefaultClient
	client.Endpoint = endpoint
	return client
}

func (client *Client) Do(tsq *TimeStampReq) (*TimeStampResp, error) {
	der, err := asn1.Marshal(tsq)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", client.Endpoint, bytes.NewBuffer(der))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/timestamp-query")

	resp, err := client.HttpClient.Do(req)
	defer resp.Body.Close()
	if err != nil {
		return nil, err
	}

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

	// Verify the response
	//err = tsr.Verify(tsq)
	//if err != nil {
	//	return tsr, err
	//}

	// Looks good
	return tsr, nil
}
