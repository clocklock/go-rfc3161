package rfc3161

// Failure Info
type PKIFailureInfo int

const (
	FailureBadAlg               = 0  // Unrecognized or unsupported Algorithm Identifier.
	FailureBadRequest           = 2  // Transaction not permitted or supported.
	FailureDataFormat           = 5  // The data submitted has the wrong format.
	FailureTimeNotAvailabe      = 14 // The TSA's time source is not available.
	FailureUnacceptedPolicy     = 15 // The requested TSA policy is not supported by the TSA.
	FailureUunacceptedExtension = 16 // The requested extension is not supported by the TSA.
	FailureAddInfoNotAvailable  = 17 // The additional information requested could not be understood or is not available.
	FailureSystemFailure        = 25 // The request cannot be handled due to system failure.
)

type PKIError struct {
	Failure PKIFailureInfo
	Cause   error
}

func (e *PKIError) Error() string {

	output := ""
	switch e.Failure {
	case FailureBadAlg:
		output += "Unrecognized or unsupported Algorithm Identifier. "
	case FailureBadRequest:
		output += "Transaction not permitted or supported. "
	case FailureDataFormat:
		output += "The data submitted has the wrong format. "
	case FailureTimeNotAvailabe:
		output += "The TSA's time source is not available. "
	case FailureUnacceptedPolicy:
		output += "The requested TSA policy is not supported by the TSA. "
	case FailureUunacceptedExtension:
		output += "The requested extension is not supported by the TSA. "
	case FailureAddInfoNotAvailable:
		output += "The additional information requested could not be understood or is not available. "
	case FailureSystemFailure:
		output += "The request cannot be handled due to system failure. "
	}

	if e.Cause != nil {
		output += e.Cause.Error()
	}

	return output
}
