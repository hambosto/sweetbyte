package types

type FileInfo struct {
	Path        string
	Size        int64
	IsEncrypted bool
	IsEligible  bool
}
