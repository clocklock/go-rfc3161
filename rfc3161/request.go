package rfc3161

import (
	"crypto"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"github.com/phayes/cryptoid"
	"math/big"
)

var (
	ErrInvalidDigestSize = errors.New("rfc3161: Invalid Message Digest. Invalid size for the given hash algorithm.")
)

type TimeStampReq struct {
	Version        int                   `asn1:"default:1"`
	MessageImprint MessageImprint        // A hash algorithm OID and the hash value of the data to be time-stamped
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"` // Identifier for the policy. For many TSA's, often the same as SignedData.DigestAlgorithm
	Nonce          *big.Int              `asn1:"optional"`
	CertReq        bool                  // If set to true, the TSA's certificate MUST be provided in the response
	Extensions     []pkix.Extension      `asn1:"optional,tag:0"`
}

type MessageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

func NewTimeStampReq(hash crypto.Hash, digest []byte) (*TimeStampReq, error) {
	if len(digest) != hash.Size() {
		return nil, ErrInvalidDigestSize
	}
	hashAlgo, err := cryptoid.HashAlgorithmByCrypto(hash)
	if err != nil {
		return nil, err
	}
	pkixAlgo := pkix.AlgorithmIdentifier{
		Algorithm: hashAlgo.OID,
	}

	tsr := new(TimeStampReq)
	tsr.Version = 1
	tsr.MessageImprint.HashAlgorithm = pkixAlgo
	tsr.MessageImprint.HashedMessage = digest

	return tsr, nil
}

func (tsr *TimeStampReq) GenerateNonce() error {
	// Generate a 128 bit nonce
	b := make([]byte, 16, 16)

	_, err := rand.Read(b)
	if err != nil {
		return err
	}

	tsr.Nonce.SetBytes(b)

	return nil
}
