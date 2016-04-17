package rfc3161

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io/ioutil"
	"math/big"
	"time"

	"github.com/phayes/cryptoid"
)

// Errors
var (
	ErrIncorrectNonce              = errors.New("rfc3161: response: Response has incorrect nonce")
	ErrNoTST                       = errors.New("rfc3161: response: Response does not contain TSTInfo")
	ErrNoCertificate               = errors.New("rfc3161: response: No certificates provided")
	ErrNoCertificateValid          = errors.New("rfc3161: response: No certificates provided signs the given TSTInfo")
	ErrMismatchedCertificates      = errors.New("rfc3161: response: Mismatched certificates")
	ErrCertificateKeyUsage         = errors.New("rfc3161: response: certificate: Invalid KeyUsage field")
	ErrCertificateExtKeyUsageUsage = errors.New("rfc3161: response: certificate: Invalid ExtKeyUsage field")
	ErrCertificateExtension        = errors.New("rfc3161: response: certificate: Missing critical timestamping extension")
	ErrInvalidSignatureDigestAlgo  = errors.New("rfc3161: response: Invalid signature digest algorithm")
)

// TimeStampResp contains a full Time Stamp Response as defined by RFC 3161
// It is also known as a "Time Stamp Reply"
// When stored into a file it should contain the extension ".tsr"
// It has a mime-type of "application/timestamp-reply"
type TimeStampResp struct {
	Status         PKIStatusInfo
	TimeStampToken `asn1:"optional"`
}

// ReadTSR reads a .tsr file into a TimeStampResp
func ReadTSR(filename string) (*TimeStampResp, error) {
	der, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	resp := new(TimeStampResp)
	rest, err := asn1.Unmarshal(der, resp)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return resp, ErrUnrecognizedData
	}
	return resp, nil
}

// Verify does a full verification of the Time Stamp Response
// including cryptographic verification of the signature
// If req.CertReq was set to true, cert may be set to nil and it will be loaded
// from the response automatically
func (resp *TimeStampResp) Verify(req *TimeStampReq, cert *x509.Certificate) error {
	tst, err := resp.GetTSTInfo()
	if err != nil {
		return err
	}

	// Verify the request for sanity's sake
	err = req.Verify()
	if err != nil {
		return err
	}

	// Verify the status
	if resp.Status.Status.IsError() {
		return &resp.Status
	}

	// Verify the nonce
	if req.Nonce == nil || tst.Nonce == nil {
		if tst.Nonce != tst.Nonce {
			return ErrIncorrectNonce
		}
	} else if req.Nonce.Cmp(tst.Nonce) != 0 {
		return ErrIncorrectNonce
	}

	// Verify the certificate
	if req.CertReq {
		reqcert, err := resp.SigningCertificate()
		if err != nil {
			return err
		}
		if cert != nil {
			if !bytes.Equal(cert.Raw, reqcert.Raw) {
				return ErrMismatchedCertificates
			}
		} else {
			cert = reqcert
		}
	}
	if cert == nil {
		return ErrNoCertificate
	}
	err = resp.VerifyCertificate(cert)
	if err != nil {
		return err
	}

	// Verify the signature
	err = resp.VerifySignature(cert)
	if err != nil {
		return err
	}

	// TODO: Review RFC3161 for other checks that are needed

	// All checks pass
	return nil
}

// SigningCertificate gets the certificate that supposedly signed the TSTInfo, if available.
// It is not guarunteed to be valid, so be sure to call VerifyCertificate() and VerifySignature()
// after obtaining the certificate.
func (resp *TimeStampResp) SigningCertificate() (*x509.Certificate, error) {
	certs, err := resp.GetCertificates()
	if err != nil {
		return nil, err
	}

	// If there is only one, just return it
	if len(certs) == 1 {
		return certs[0], nil
	}

	// There is more than one, search for one that is valid
	for _, cert := range certs {
		// First check to make sure it's the right kind of certificate
		if err := resp.VerifyCertificate(cert); err != nil {
			continue
		}

		// Check that it signed the TSTInfo
		if err := resp.VerifySignature(cert); err != nil {
			continue
		}

		return cert, nil
	}

	return nil, ErrNoCertificateValid
}

// VerifyCertificate verifies that the certificate was set up correctly for key signing,
// is proprely referenced within the reponse, and has a valid signature chain.
//
// WARNING: Does not do any revocation checking
func (resp *TimeStampResp) VerifyCertificate(cert *x509.Certificate) error {
	if cert == nil {
		return ErrNoCertificate
	}

	// Key usage must contain the KeyUsageDigitalSignature bit
	// and MAY contain the non-repudiation / content-commitment bit
	if cert.KeyUsage != x509.KeyUsageDigitalSignature && cert.KeyUsage != (x509.KeyUsageDigitalSignature+x509.KeyUsageContentCommitment) {
		return ErrCertificateKeyUsage
	}

	// Next check the extended key usage
	// Only one ExtKeyUsage may be defined as per RFC 3161
	if len(cert.ExtKeyUsage) != 1 {
		return ErrCertificateExtKeyUsageUsage
	}
	if cert.ExtKeyUsage[0] != x509.ExtKeyUsageTimeStamping {
		return ErrCertificateExtKeyUsageUsage
	}

	// Check to make sure it has the correct extension
	// Only one Extended Key Usage may be defined, it must be critical,
	// and it must be OidExtKeyUsageTimeStamping
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OidExtKeyUsage) {
			if !ext.Critical {
				return ErrCertificateExtKeyUsageUsage
			}
			var rfc3161Ext []asn1.ObjectIdentifier
			_, err := asn1.Unmarshal(ext.Value, &rfc3161Ext)
			if err != nil {
				return err
			}
			if len(rfc3161Ext) != 1 {
				return ErrCertificateExtKeyUsageUsage
			}
			if !rfc3161Ext[0].Equal(OidExtKeyUsageTimeStamping) {
				return ErrCertificateExtKeyUsageUsage
			}
		}
	}

	// Check to make sure the DigestAlgorithm specified in the response matches the certificate
	if len(resp.DigestAlgorithms) == 0 {
		return ErrInvalidSignatureDigestAlgo
	}
	digestAlgo, err := cryptoid.HashAlgorithmByOID(resp.DigestAlgorithms[0].Algorithm.String())
	if err != nil {
		return err
	}
	sigAlgo := cryptoid.SignatureAlgorithmByX509(cert.SignatureAlgorithm)
	if sigAlgo.HashAlgorithm.Name != digestAlgo.Name {
		return ErrInvalidSignatureDigestAlgo
	}

	// Verify the certificate chain
	opts := x509.VerifyOptions{
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}
	_, err = cert.Verify(opts)
	if err != nil {
		return err
	}

	return nil
}

// VerifySignature Verifies that the given certificate signed the TSTInfo
func (resp *TimeStampResp) VerifySignature(cert *x509.Certificate) error {
	return cert.CheckSignature(cert.SignatureAlgorithm, []byte(resp.EContent), cert.Signature)
}

// TimeStampToken is a wrapper than contains the OID for a TimeStampToken
// as well as the wrapped SignedData
type TimeStampToken struct {
	ContentType asn1.ObjectIdentifier // MUST BE OidSignedData
	SignedData  `asn1:"tag:0,explicit,optional"`
}

// SignedData is a shared-standard as defined by RFC 2630
type SignedData struct {
	Version          int                        `asn1:"default:4"`
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapsulatedContentInfo
	Certificates asn1.RawValue          `asn1:"optional,set,tag:0"` // Certificate DER. Use GetCertificates() to get the x509.Certificate list
	CRLs         []pkix.CertificateList `asn1:"optional,tag:1"`
	SignerInfos  []SignerInfo           `asn1:"optional,set"` // Not optional in the spec, but optional in the OpenSSL implementation
}

// GetCertificates gets a list of x509.Certificate objects from the DER encoded Certificates field
func (sd *SignedData) GetCertificates() ([]*x509.Certificate, error) {
	if len(sd.Certificates.Bytes) == 0 {
		return nil, ErrNoCertificate
	}
	return x509.ParseCertificates(sd.Certificates.Bytes)
}

// SignerInfo is a shared-standard as defined by RFC 2630
type SignerInfo struct {
	Version            int                   `asn1:"default:1"`
	SID                IssuerAndSerialNumber // Not supporting CHOICE subjectKeyIdentifier
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        []Attribute `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAtrributes []Attribute `asn1:"optional,tag:1"`
}

// IssuerAndSerialNumber is defined in RFC 2630
type IssuerAndSerialNumber struct {
	IssuerName   pkix.RDNSequence
	SerialNumber *big.Int
}

// Attribute is defined in RFC 2630
type Attribute struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

// EncapsulatedContentInfo is defined in RFC 2630
//
// The fields of type EncapsulatedContentInfo of the SignedData
// construct have the following meanings:
//
// eContentType is an object identifier that uniquely specifies the
// content type.  For a time-stamp token it is defined as:
//
// id-ct-TSTInfo  OBJECT IDENTIFIER ::= { iso(1) member-body(2)
// us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) ct(1) 4}
//
// eContent is the content itself, carried as an octet string.
// The eContent SHALL be the DER-encoded value of TSTInfo.
//
// The time-stamp token MUST NOT contain any signatures other than the
// signature of the TSA.  The certificate identifier (ESSCertID) of the
// TSA certificate MUST be included as a signerInfo attribute inside a
// SigningCertificate attribute.
type EncapsulatedContentInfo struct {
	EContentType asn1.ObjectIdentifier // MUST BE OidContentTypeTSTInfo
	EContent     asn1.RawContent       `asn1:"explicit,optional,tag:0"` // DER encoding of TSTInfo
}

// GetTSTInfo unpacks the DER encoded TSTInfo and returns it
func (eci *EncapsulatedContentInfo) GetTSTInfo() (*TSTInfo, error) {
	if len(eci.EContent) == 0 {
		return nil, ErrNoTST
	}

	tstinfo := new(TSTInfo)
	rest, err := asn1.Unmarshal(eci.EContent, tstinfo)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return tstinfo, ErrUnrecognizedData
	}

	return tstinfo, nil
}

// TSTInfo is the acutal DER signed data and represents the core of the Time Stamp Reponse.
// It contains the time-stamp, the accuracy, and all other pertinent informatuon
type TSTInfo struct {
	Version        int                   `json:"version" asn1:"default:1"`
	Policy         asn1.ObjectIdentifier `json:"policy"`                           // Identifier for the policy. For many TSA's, often the same as SignedData.DigestAlgorithm
	MessageImprint MessageImprint        `json:"message-imprint"`                  // MUST have the same value of MessageImprint in matching TimeStampReq
	SerialNumber   *big.Int              `json:"serial-number"`                    // Time-Stamping users MUST be ready to accommodate integers up to 160 bits
	GenTime        time.Time             `json:"gen-time"`                         // The time at which it was stamped
	Accuracy       Accuracy              `json:"accuracy" asn1:"optional"`         // Accuracy represents the time deviation around the UTC time.
	Ordering       bool                  `json:"ordering" asn1:"optional"`         // True if SerialNumber increases monotonically with time.
	Nonce          *big.Int              `json:"nonce" asn1:"optional"`            // MUST be present if the similar field was present in TimeStampReq.  In that case it MUST have the same value.
	TSA            asn1.RawValue         `json:"tsa" asn1:"optional,tag:0"`        // This is a CHOICE (See RFC 3280 for all choices). See https://github.com/golang/go/issues/13999 for information on handling.
	Extensions     []pkix.Extension      `json:"extensions" asn1:"optional,tag:1"` // List of extensions
}

// Accuracy represents the time deviation around the UTC time.
//
// If either seconds, millis or micros is missing, then a value of zero
// MUST be taken for the missing field.
//
// By adding the accuracy value to the GeneralizedTime, an upper limit
// of the time at which the time-stamp token has been created by the TSA
// can be obtained.  In the same way, by subtracting the accuracy to the
// GeneralizedTime, a lower limit of the time at which the time-stamp
// token has been created by the TSA can be obtained.
//
// Accuracy can be decomposed in seconds, milliseconds (between 1-999)
// and microseconds (1-999), all expressed as integer.
//
// When the accuracy field is not present, then the accuracy
// may be available through other means, e.g., the TSAPolicyId.
type Accuracy struct {
	Seconds int `asn1:"optional"`
	Millis  int `asn1:"optional,tag:0"`
	Micros  int `asn1:"optional,tag:1"`
}

// Duration gets the time.Duration representation of the Accuracy
func (acc *Accuracy) Duration() time.Duration {
	return (time.Duration(acc.Seconds) * time.Second) + (time.Duration(acc.Millis) * time.Millisecond) + (time.Duration(acc.Micros) + time.Microsecond)
}
