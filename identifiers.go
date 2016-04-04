package rfc3161

import (
	"crypto/x509"
	"encoding/asn1"
)

var (
	// X.509
	OidSignatureMD2WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 2}
	OidSignatureMD5WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}
	OidSignatureSHA1WithRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	OidSignatureSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	OidSignatureSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	OidSignatureSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	OidSignatureDSAWithSHA1     = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}
	OidSignatureDSAWithSHA256   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 4, 3, 2}
	OidSignatureECDSAWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	OidSignatureECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	OidSignatureECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	OidSignatureECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
)

var (
	// RFC-2630: iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs7(7) 2
	OidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

	// RFC-3161: iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) ct(1) 4
	OidContentTypeTSTInfo = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
)

func GetSignatureAlgorithmFromOID(oid asn1.ObjectIdentifier) x509.SignatureAlgorithm {
	switch {
	case oid.Equal(OidSignatureMD2WithRSA):
		return x509.MD2WithRSA
	case oid.Equal(OidSignatureMD5WithRSA):
		return x509.MD5WithRSA
	case oid.Equal(OidSignatureSHA1WithRSA):
		return x509.SHA1WithRSA
	case oid.Equal(OidSignatureSHA256WithRSA):
		return x509.SHA256WithRSA
	case oid.Equal(OidSignatureSHA384WithRSA):
		return x509.SHA384WithRSA
	case oid.Equal(OidSignatureSHA512WithRSA):
		return x509.SHA512WithRSA
	case oid.Equal(OidSignatureDSAWithSHA1):
		return x509.DSAWithSHA1
	case oid.Equal(OidSignatureDSAWithSHA256):
		return x509.DSAWithSHA256
	case oid.Equal(OidSignatureECDSAWithSHA1):
		return x509.ECDSAWithSHA1
	case oid.Equal(OidSignatureECDSAWithSHA256):
		return x509.ECDSAWithSHA256
	case oid.Equal(OidSignatureECDSAWithSHA384):
		return x509.ECDSAWithSHA384
	case oid.Equal(OidSignatureECDSAWithSHA512):
		return x509.ECDSAWithSHA512
	}
	return x509.UnknownSignatureAlgorithm
}
