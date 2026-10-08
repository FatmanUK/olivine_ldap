package ldap

// ResultCode is an LDAP result code, from include/ldap.h:
// 612-700. The values are hex there and are kept hex here so
// the two can be compared by eye.
type ResultCode int32

const (
	Success                 ResultCode = 0x00
	OperationsError         ResultCode = 0x01
	ProtocolError           ResultCode = 0x02
	TimeLimitExceeded       ResultCode = 0x03
	SizeLimitExceeded       ResultCode = 0x04
	CompareFalse            ResultCode = 0x05
	CompareTrue             ResultCode = 0x06
	AuthMethodNotSupported  ResultCode = 0x07
	StrongerAuthRequired    ResultCode = 0x08
	Referral                ResultCode = 0x0a
	AdminLimitExceeded      ResultCode = 0x0b
	UnavailableCriticalExt  ResultCode = 0x0c
	ConfidentialityRequired ResultCode = 0x0d
	SASLBindInProgress      ResultCode = 0x0e
	NoSuchAttribute         ResultCode = 0x10
	UndefinedType           ResultCode = 0x11
	InappropriateMatching   ResultCode = 0x12
	ConstraintViolation     ResultCode = 0x13
	TypeOrValueExists       ResultCode = 0x14
	InvalidSyntax           ResultCode = 0x15
	NoSuchObject            ResultCode = 0x20
	AliasProblem            ResultCode = 0x21
	InvalidDNSyntax         ResultCode = 0x22
	AliasDerefProblem       ResultCode = 0x24
	InappropriateAuth       ResultCode = 0x30
	InvalidCredentials      ResultCode = 0x31
	InsufficientAccess      ResultCode = 0x32
	Busy                    ResultCode = 0x33
	Unavailable             ResultCode = 0x34
	UnwillingToPerform      ResultCode = 0x35
	LoopDetect              ResultCode = 0x36
	NamingViolation         ResultCode = 0x40
	ObjectClassViolation    ResultCode = 0x41
	NotAllowedOnNonLeaf     ResultCode = 0x42
	NotAllowedOnRDN         ResultCode = 0x43
	AlreadyExists           ResultCode = 0x44
	NoObjectClassMods       ResultCode = 0x45
	AffectsMultipleDSAs     ResultCode = 0x47
	Other                   ResultCode = 0x50
)

// names are the diagnostics upstream uses. Where a name here
// differs from the C macro it follows RFC 4511 instead:
// LDAP_STRONG_AUTH_REQUIRED is strongerAuthRequired in the
// RFC, for instance.
var names = map[ResultCode]string{
	Success:                 "success",
	OperationsError:         "operationsError",
	ProtocolError:           "protocolError",
	TimeLimitExceeded:       "timeLimitExceeded",
	SizeLimitExceeded:       "sizeLimitExceeded",
	CompareFalse:            "compareFalse",
	CompareTrue:             "compareTrue",
	AuthMethodNotSupported:  "authMethodNotSupported",
	StrongerAuthRequired:    "strongerAuthRequired",
	Referral:                "referral",
	AdminLimitExceeded:      "adminLimitExceeded",
	UnavailableCriticalExt:  "unavailableCriticalExtension",
	ConfidentialityRequired: "confidentialityRequired",
	SASLBindInProgress:      "saslBindInProgress",
	NoSuchAttribute:         "noSuchAttribute",
	UndefinedType:           "undefinedAttributeType",
	InappropriateMatching:   "inappropriateMatching",
	ConstraintViolation:     "constraintViolation",
	TypeOrValueExists:       "attributeOrValueExists",
	InvalidSyntax:           "invalidAttributeSyntax",
	NoSuchObject:            "noSuchObject",
	AliasProblem:            "aliasProblem",
	InvalidDNSyntax:         "invalidDNSyntax",
	AliasDerefProblem:       "aliasDereferencingProblem",
	InappropriateAuth:       "inappropriateAuthentication",
	InvalidCredentials:      "invalidCredentials",
	InsufficientAccess:      "insufficientAccessRights",
	Busy:                    "busy",
	Unavailable:             "unavailable",
	UnwillingToPerform:      "unwillingToPerform",
	LoopDetect:              "loopDetect",
	NamingViolation:         "namingViolation",
	ObjectClassViolation:    "objectClassViolation",
	NotAllowedOnNonLeaf:     "notAllowedOnNonLeaf",
	NotAllowedOnRDN:         "notAllowedOnRDN",
	AlreadyExists:           "entryAlreadyExists",
	NoObjectClassMods:       "objectClassModsProhibited",
	AffectsMultipleDSAs:     "affectsMultipleDSAs",
	Other:                   "other",
}

// String names the result code.
func (c ResultCode) String() string {
	if s, ok := names[c]; ok {
		return s
	}
	return "unknown"
}

// IsSuccess reports whether c closes an operation happily.
// compareTrue and compareFalse both do: a compare that
// answers is not a compare that failed.
func (c ResultCode) IsSuccess() bool {
	return c == Success || c == CompareTrue ||
		c == CompareFalse
}
