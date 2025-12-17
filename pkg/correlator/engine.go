package correlator

// CorrelationEngine - Links network events with file events
// TODO: Implement in Iteration 2
type CorrelationEngine struct {
	// Will be populated in Iteration 2
}

type DependencyChain struct {
	PackageName      string
	DeclaredVersion  string
	ActualVersion    string
	DownloadURL      string
	DownloadIP       string
	FilesWritten     []string
	Checksum         string
	Verified         bool
	PackageManager   string
}

func NewCorrelationEngine() *CorrelationEngine {
	return &CorrelationEngine{}
}
