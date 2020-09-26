package rfc3161

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"mime"
)

// Misc Errors
var (
	ErrUnrecognizedData = errors.New("rfc3161: Got unrecognized data and end of DER")
)

// OID Identifiers
var (
	// RFC-5280: { id-kp 8 }
	// RFC-3161: {iso(1) identified-organization(3) dod(6) internet(1) security(5) mechanisms(5) pkix(7) kp (3) timestamping (8)}
	OidExtKeyUsageTimeStamping = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}

	// Certificate extension: "extKeyUsage": {joint-iso-itu-t(2) ds(5) certificateExtension(29) extKeyUsage(37)}
	OidExtKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}

	// RFC-5652: Content Type: {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9) contentType(3)}
	OidContentType = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}

	// RFC-5652: Message Digest: {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9) messageDigest(4)}
	OidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}

	// RFC-5652: iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs7(7) 2
	OidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

	// RFC-3161: iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) ct(1) 4
	OidContentTypeTSTInfo = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}

	// RFC-3161: iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) aa(2) 14
	OidContentTypeTimeStampToken = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}
)

// Supported Extensions.
var supportedExtensions []asn1.ObjectIdentifier

// RootCerts is any additional trusted root certificates.
// It should only be used for testing.
// It must be initialized with x509.NewCertPool
var RootCerts *x509.CertPool

// RegisterExtension registers a supported Extension.
// This is intended to be called from the init function in
// packages that implement support for these extensions.
// A TimeStampReq or TimeStampResp with an unregistered
// critical extension will return an error when verified.
func RegisterExtension(extension asn1.ObjectIdentifier) {
	if supportedExtensions == nil {
		supportedExtensions = make([]asn1.ObjectIdentifier, 0, 0)
	}

	// Check if it already exists
	for _, ext := range supportedExtensions {
		if ext.Equal(extension) {
			return
		}
	}

	// Add it
	supportedExtensions = append(supportedExtensions, extension)
}

// ListExtensions lists all supported extensions
func ListExtensions() []asn1.ObjectIdentifier {
	if supportedExtensions == nil {
		return make([]asn1.ObjectIdentifier, 0, 0)
	} else {
		return supportedExtensions
	}
}

func setMimeTypes() error {
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
	if err := setMimeTypes(); err != nil {
		panic(err)
	}
}
