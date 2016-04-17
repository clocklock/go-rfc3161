package rfc3161

// PKIStatusInfo contains complete information about the status of the Time Stamp Response
type PKIStatusInfo struct {
	Status       PKIStatus
	StatusString string         `asn1:"optional,utf8"`
	FailInfo     PKIFailureInfo `asn1:"optional"`
}

func (si *PKIStatusInfo) Error() string {
	var output string
	output += si.Status.Error()
	if si.Status.IsError() {
		output += ": " + si.FailInfo.Error()
	}
	if si.StatusString != "" {
		output += ": " + si.StatusString
	}
	return output
}

// PKIStatus carries the specific status code about the status of the Time Stamp Response.
type PKIStatus int

// When the status contains the value zero or one, a TimeStampToken MUST
// be present.  When status contains a value other than zero or one, a
// TimeStampToken MUST NOT be present.  One of the following values MUST
//  be contained in status
const (
	StatusGranted                = iota // When the PKIStatus contains the value zero a TimeStampToken, as requested, is present.
	StatusGrantedWithMods               // When the PKIStatus contains the value one a TimeStampToken, with modifications, is present.
	StatusRejection                     // When the request is invalid or otherwise rejected.
	StatusWaiting                       // When the request is being processed and the client should check back later.
	StatusRevocationWarning             // Warning that a revocation is imminent.
	StatusRevocationNotification        // Notification that a revocation has occurred.
)

// IsError checks if the given Status is an error
func (status PKIStatus) IsError() bool {
	return (status != StatusGranted && status != StatusGrantedWithMods && status != StatusWaiting)
}

func (status PKIStatus) Error() string {
	switch status {
	case StatusGranted:
		return "A TimeStampToken, as requested, is present"
	case StatusGrantedWithMods:
		return "A TimeStampToken, with modifications, is present"
	case StatusRejection:
		return "The request is invalid or otherwise rejected"
	case StatusWaiting:
		return "The request is being processed and the client should check back later"
	case StatusRevocationWarning:
		return "A revocation is imminent"
	case StatusRevocationNotification:
		return "A revocation has occurred"
	default:
		return "Invalid PKIStatus"
	}
}

// PKIFailureInfo as defined by RFC 3161 2.4.2
type PKIFailureInfo int

// When the TimeStampToken is not present, the failInfo indicates the reason why the time-stamp
// request was rejected and may be one of the following values.
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

func (fi PKIFailureInfo) Error() string {
	switch fi {
	case FailureBadAlg:
		return "Unrecognized or unsupported Algorithm Identifier"
	case FailureBadRequest:
		return "Transaction not permitted or supported"
	case FailureDataFormat:
		return "The data submitted has the wrong format"
	case FailureTimeNotAvailabe:
		return "The TSA's time source is not available"
	case FailureUnacceptedPolicy:
		return "The requested TSA policy is not supported by the TSA"
	case FailureUunacceptedExtension:
		return "The requested extension is not supported by the TSA"
	case FailureAddInfoNotAvailable:
		return "The additional information requested could not be understood or is not available"
	case FailureSystemFailure:
		return "The request cannot be handled due to system failure"
	default:
		return "Invalid PKIFailureInfo"
	}
}
