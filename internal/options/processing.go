package options

type Processing int

const (
	Encryption	Processing	= iota
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
