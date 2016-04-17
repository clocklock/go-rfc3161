package rfc3161

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io/ioutil"
	"math/big"
	"time"
)

// Errors
var (
	ErrIncorrectNonce = errors.New("rfc3161: response: Response has incorrect nonce")
	ErrNoTST          = errors.New("rfc3161: response: Response does not contain TSTInfo")
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
func (resp *TimeStampResp) Verify(req *TimeStampReq) error {
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

	// Verify... TODO

	// All checks pass
	return nil
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
	Certificates asn1.RawValue          `asn1:"optional,tag:0"` //TODO: Support
	CRLs         []pkix.CertificateList `asn1:"optional,tag:1"`
	SignerInfos  []SignerInfo           `asn1:"optional,set"` // Not optional in the spec, but optional in the OpenSSL implementation
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
	Version        int                   `asn1:"default:1"`
	Policy         asn1.ObjectIdentifier // Identifier for the policy. For many TSA's, often the same as SignedData.DigestAlgorithm
	MessageImprint MessageImprint        // MUST have the same value of MessageImprint in matching TimeStampReq
	SerialNumber   *big.Int              // Time-Stamping users MUST be ready to accommodate integers up to 160 bits
	GenTime        time.Time             // The time at which it was stamped
	Accuracy       Accuracy              `asn1:"optional"`
	Ordering       bool                  `asn1:"optional"`       // True if SerialNumber increases monotonically with time.
	Nonce          *big.Int              `asn1:"optional"`       // MUST be present if the similar field was present in TimeStampReq.  In that case it MUST have the same value.
	TSA            asn1.RawValue         `asn1:"optional,tag:0"` // TODO: GeneralName from PKIX1Implicit88... pkix.RDNSequence?
	Extensions     []pkix.Extension      `asn1:"optional,tag:1"`
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
