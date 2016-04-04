package rfc3161

import (
	"crypto"
	"crypto/sha1"
	"encoding/asn1"
	"io/ioutil"
	"testing"
)

import "github.com/davecgh/go-spew/spew"

func TestTSR(t *testing.T) {
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

	// Contruct the same tsr manually
	mes, err := ioutil.ReadFile("./test/message.txt")
	if err != nil {
		t.Error(err)
	}
	digest := sha1.Sum(mes)

	tsr2, err := NewTimeStampReq(crypto.SHA1, digest[:])
	if err != nil {
		t.Error(err)
	}
}
