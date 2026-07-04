package common

// ServiceSender abstracts service-level fingerprint requests.
type ServiceSender interface {
	Send(host string, portStr string, data []byte, network string) ([]byte, error)
}

// ServiceCallback is a callback for service fingerprint detection results.
type ServiceCallback func(*ServiceResult)
