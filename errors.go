package rfc3161

// Failure Info
type PKIFailureInfo int

const (
	FailureBadAlg               = 0  // Unrecognized or unsupported Algorithm Identifier
	FailureBadRequest           = 2  // Transaction not permitted or supported
	FailureDataFormat           = 5  // The data submitted has the wrong format
	FailureTimeNotAvailabe      = 14 // The TSA's time source is not available
	FailureUnacceptedPolicy     = 15 // The requested TSA policy is not supported by the TSA.
	FailureUunacceptedExtension = 16 // The requested extension is not supported by the TSA.
	FailureAddInfoNotAvailable  = 17 // The additional information requested could not be understood or is not available
	FailureSystemFailure        = 25 // The request cannot be handled due to system failure
)
