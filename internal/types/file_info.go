package types

// FileInfo represents file information for processing.
type FileInfo struct {
	Path        string
	Size        int64
	IsEncrypted bool
	IsEligible  bool
}
