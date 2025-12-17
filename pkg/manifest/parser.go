package manifest

// Manifest represents a parsed package manager manifest
// TODO: Implement in Iteration 2
type Manifest struct {
	Type     string
	Path     string
	Packages []DeclaredPackage
}

type DeclaredPackage struct {
	Name       string
	Version    string
	Constraint string
}

func ParseManifest(path string) (*Manifest, error) {
	// TODO: Implement manifest parsing in Iteration 2
	return nil, nil
}
