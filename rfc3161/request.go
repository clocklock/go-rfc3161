package rfc3161

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
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
