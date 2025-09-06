package options

type ProcessorMode string

const (
	ModeEncrypt ProcessorMode = "Encrypt"
	ModeDecrypt ProcessorMode = "Decrypt"
)

type DeleteOption string

const (
	DeleteStandard DeleteOption = "Normal Delete (faster, but recoverable)"
	DeleteSecure   DeleteOption = "Secure Delete (slower, but unrecoverable)"
)
