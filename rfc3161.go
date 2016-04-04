package rfc3161

import (
	"mime"
)

// Configuration
// Set InitMimeTypes to initialize mimetimes for timestamp-query and timestamp-reply
var InitMimeTypes bool

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
	if InitMimeTypes {
		err := SetMimeTypes()
		if err != nil {
			panic(err)
		}
	}
}
