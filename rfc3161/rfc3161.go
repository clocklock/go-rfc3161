package rfc3161

import (
	"encoding/asn1"
	"github.com/cryptoballot/entropychecker"
	"mime"
)

// OID Identifiers
var (
	// RFC-2630: iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs7(7) 2
	OidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

	// RFC-3161: iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) ct(1) 4
	OidContentTypeTSTInfo = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
)

func SetMimeTypes() error {
	err := mime.AddExtensionType(".tsq", "application/timestamp-query")
	if err != nil {
		return err
	}

	err = mime.AddExtensionType(".tsr", "application/timestamp-reply")
	if err != nil {
		return err
	}

	return nil
}

func init() {
	// Make sure we have sufficient entropy and fail to start if there isn't
	// This only works on Linux.
	err := entropychecker.WaitForEntropy()
	if err != nil && err != entropychecker.ErrUnsupportedOS {
		panic(err)
	}

	err = SetMimeTypes()
	if err != nil {
		panic(err)
	}
}
