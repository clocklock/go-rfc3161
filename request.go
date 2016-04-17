package rfc3161

import (
	"crypto"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io/ioutil"
	"math/big"

	"github.com/phayes/cryptoid"
)

// Errors
var (
	ErrInvalidDigestSize = errors.New("rfc3161: Invalid Message Digest. Invalid size for the given hash algorithm")
	ErrUnsupportedHash   = errors.New("rfc3161: Unsupported Hash Algorithm")
	ErrUnsupportedExt    = errors.New("rfc3161: Unsupported Critical Extension")
)

// TimeStampReq contains a full Time Stamp Request as defined by RFC 3161
// It is also known as a "Time Stamp Query"
// When stored into a file it should contain the extension ".tsq"
// It has a mime-type of "application/timestamp-query"
type TimeStampReq struct {
	Version        int                   `asn1:"default:1"`
	MessageImprint MessageImprint        // A hash algorithm OID and the hash value of the data to be time-stamped
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"` // Identifier for the policy. For many TSA's, often the same as SignedData.DigestAlgorithm
	Nonce          *big.Int              `asn1:"optional"` // Nonce could be up to 160 bits
	CertReq        bool                  `asn1:"optional"` // If set to true, the TSA's certificate MUST be provided in the response.
	Extensions     []pkix.Extension      `asn1:"optional,tag:0"`
}

// MessageImprint contains hash algorithm OID and the hash digest of the data to be time-stamped
type MessageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

// NewTimeStampReq creates a new Time Stamp Request, given a crypto.Hash algorithm and a message digest
func NewTimeStampReq(hash crypto.Hash, digest []byte) (*TimeStampReq, error) {
	tsr := new(TimeStampReq)
	tsr.Version = 1

	err := tsr.SetHashDigest(hash, digest)
	if err != nil {
		return nil, err
	}

	return tsr, nil
}

// ReadTSQ reads a .tsq file into a TimeStampReq
func ReadTSQ(filename string) (*TimeStampReq, error) {
	der, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	req := new(TimeStampReq)
	rest, err := asn1.Unmarshal(der, req)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return req, ErrUnrecognizedData
	}
	return req, nil
}

// SetHashDigest sets the Hash Algorithm and the Hash Digest for the Time Stamp Request
func (tsr *TimeStampReq) SetHashDigest(hash crypto.Hash, digest []byte) error {
	if len(digest) != hash.Size() {
		return ErrInvalidDigestSize
	}
	pkixAlgo := pkix.AlgorithmIdentifier{
		Algorithm: cryptoid.HashAlgorithmByCrypto(hash).OID,
	}

	tsr.MessageImprint.HashAlgorithm = pkixAlgo
	tsr.MessageImprint.HashedMessage = digest

	return nil
}

// GetHash will get the crypto.Hash for the Time Stamp Request
// The Hash will be 0 if it is not recognized
func (tsr *TimeStampReq) GetHash() crypto.Hash {
	hashAlgo, err := cryptoid.HashAlgorithmByOID(tsr.MessageImprint.HashAlgorithm.Algorithm.String())
	if err != nil {
		return 0
	}
	return hashAlgo.Hash
}

// GenerateNonce generates a 128 bit nonce for the Time Stamp Request
// If a different size is required then set manually with tsr.Nonce.SetBytes()
func (tsr *TimeStampReq) GenerateNonce() error {
	// Generate a 128 bit nonce
	b := make([]byte, 16, 16)

	_, err := rand.Read(b)
	if err != nil {
		return err
	}

	tsr.Nonce = new(big.Int)
	tsr.Nonce.SetBytes(b)

	return nil
}

// Verify does a basic sanity check of the Time Stamp Request
// Checks to make sure the hash is supported, the digest matches the hash,
// and no unsupported critical extensions exist. Be sure to add all supported
// extentions to rfc3161.SupportedExtensions.
func (tsr *TimeStampReq) Verify() error {
	hash := tsr.GetHash()
	if hash == 0 {
		return ErrUnsupportedHash
	}
	if len(tsr.MessageImprint.HashedMessage) != hash.Size() {
		return ErrInvalidDigestSize
	}

	// Check for any unsupported critical extensions
	// Critical Extensions should be registered in rfc3161.SupportedExtensions
	if tsr.Extensions != nil {
		for _, ext := range tsr.Extensions {
			if ext.Critical {
				supported := false
				if supportedExtensions != nil {
					for _, se := range supportedExtensions {
						if se.Equal(ext.Id) {
							supported = true
							break
						}
					}
				}
				if !supported {
					return ErrUnsupportedExt
				}
			}
		}
	}

	return nil
}
