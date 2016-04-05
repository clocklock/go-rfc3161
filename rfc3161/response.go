package rfc3161

import (
	//"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"time"
)

// Errors
var (
	ErrIncorrectNonce = errors.New("rfc3161: response: Response has incorrect nonce.")
)

// Status Codes
type PKIStatus int

const (
	StatusGranted                = iota // When the PKIStatus contains the value zero a TimeStampToken, as requested, is present.
	StatusGrantedWithMods               // When the PKIStatus contains the value one a TimeStampToken, with modifications, is present.
	StatusRejection                     // When the request is invalid or otherwise rejected.
	StatusWaiting                       // When the request is being processed and the client should check back later.
	StatusRevocationWarning             // Warning that a revocation is imminent.
	StatusRevocationNotification        // Notification that a revocation has occurred.
)

func (status PKIStatus) IsError() bool {
	if status != StatusGranted && status != StatusGrantedWithMods && status != StatusWaiting {
		return true
	} else {
		return false
	}
}

type TimeStampResp struct {
	Status         PKIStatusInfo
	TimeStampToken `asn1:"optional"`
}

type PKIStatusInfo struct {
	Status       PKIStatus
	StatusString string         `asn1:"optional,utf8"`
	FailInfo     PKIFailureInfo `asn1:"optional"`
}

type TimeStampToken struct {
	ContentType asn1.ObjectIdentifier // MUST BE OidSignedData
	SignedData  `asn1:"tag:0,explicit,optional"`
}

// See RFC 2630
type SignedData struct {
	Version          int                        `asn1:"default:4"`
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapsulatedContentInfo
	Certificates asn1.RawValue          `asn1:"optional,tag:0"` //TODO: Support
	CRLs         []pkix.CertificateList `asn1:"optional,tag:1"`
	SignerInfos  []SignerInfo           `asn1:"set"`
}

// See RFC 2630
type SignerInfo struct {
	Version            int                   `asn1:"default:1"`
	SID                IssuerAndSerialNumber // Not supporting CHOICE subjectKeyIdentifier
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        []Attribute `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAtrributes []Attribute `asn1:"optional,tag:1"`
}

// See RFC 2630
type IssuerAndSerialNumber struct {
	IssuerName   pkix.RDNSequence // Name from X.501 // TODO Support
	SerialNumber *big.Int
}

// See RFC 2630
type Attribute struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

// See RFC 2630
type EncapsulatedContentInfo struct {
	EContentType asn1.ObjectIdentifier // MUST BE OidContentTypeTSTInfo
	EContent     []byte                `asn1:"explicit,optional,tag:0"` // DER encoding of TSTInfo
}

func (eci *EncapsulatedContentInfo) GetTSTInfo() (*TSTInfo, error) {
	tst := new(TSTInfo)
	_, err := asn1.Unmarshal(eci.EContent, tst)
	if err != nil {
		return nil, err
	}
	return tst, nil
}

type TSTInfo struct {
	Version        int                   `asn1:"default:1"`
	Policy         asn1.ObjectIdentifier // Identifier for the policy. For many TSA's, often the same as SignedData.DigestAlgorithm
	MessageImprint MessageImprint        // MUST have the same value of MessageImprint in matching TimeStampReq
	SerialNumber   big.Int               // Time-Stamping users MUST be ready to accommodate integers up to 160 bits
	GenTime        time.Time             // The time at which it was stamped
	Accuracy       Accuracy              `asn1:"optional`
	Ordering       bool                  // True if SerialNumber increases monotonically with time.
	Nonce          *big.Int              // MUST be present if the similar field was present in TimeStampReq.  In that case it MUST have the same value.
	TSA            asn1.RawValue         `asn1:"optional,tag:0"` // GeneralName from PKIX1Implicit88
	Extensions     []pkix.Extension      `asn1:"optional,tag:1"`
}

type Accuracy struct {
	Seconds int `asn1:"optional"`
	Millis  int `asn1:"optional,tag:0"`
	Micros  int `asn1:"optional,tag:1"`
}
