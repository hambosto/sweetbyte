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

type Processing int

const (
	Encryption Processing = iota
	Decryption
)

func (p Processing) String() string {
	switch p {
	case Encryption:
		return "Encrypting..."
	case Decryption:
		return "Decrypting..."
	default:
		return "Processing..."
	}
}
