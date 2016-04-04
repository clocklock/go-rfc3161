package rfc3161

import (
	"crypto"
	"crypto/sha1"
	"encoding/asn1"
	"io/ioutil"
	"testing"
)

import "github.com/davecgh/go-spew/spew"

func TestTSRUnmarshal(t *testing.T) {
	der, err := ioutil.ReadFile("./test/sha1.tsq")
	if err != nil {
		t.Error(err)
	}

	tsr := new(TimeStampReq)
	rest, err := asn1.Unmarshal(der, tsr)
	if err != nil {
		t.Error(err)
	}
	if len(rest) != 0 {
		t.Error("Got unrecognized data in the TSR")
	}
	err = tsr.Verify()
	if err != nil {
		t.Error(err)
	}
}

// Contruct the tsr manually
func TestTSRBuildManually(t *testing.T) {
	mes, err := ioutil.ReadFile("./test/message.txt")
	if err != nil {
		t.Error(err)
	}
	digest := sha1.Sum(mes)

	tsr2, err := NewTimeStampReq(crypto.SHA1, digest[:])
	if err != nil {
		t.Error(err)
	}
	err = tsr2.GenerateNonce()
	if err != nil {
		t.Error(err)
	}
	err = tsr2.Verify()
	if err != nil {
		t.Error(err)
	}

	spew.Dump(tsr2)
}
