package alert

// Alert - Represents a security alert
// TODO: Implement in Iteration 3
type Alert struct {
	Severity string
	Type     string
	Message  string
	Package  string
	Domain   string
}

type AlertManager struct {
	// Will be populated in Iteration 3
}

func NewAlertManager() *AlertManager {
	return &AlertManager{}
}
