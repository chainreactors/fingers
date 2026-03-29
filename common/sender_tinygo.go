//go:build tinygo
// +build tinygo

package common

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ServiceSender abstracts service-level fingerprint requests.
type ServiceSender interface {
	Send(host string, portStr string, data []byte, network string) ([]byte, error)
}

// DefaultServiceSender sends TCP/UDP/TLS probes with a timeout.
type DefaultServiceSender struct {
	timeout time.Duration
}

func NewServiceSender(timeout time.Duration) ServiceSender {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &DefaultServiceSender{timeout: timeout}
}

func (d *DefaultServiceSender) Send(host string, portStr string, data []byte, network string) ([]byte, error) {
	port, actualNetwork := d.parsePortString(portStr, network)
	target := fmt.Sprintf("%s:%d", host, port)

	switch strings.ToLower(actualNetwork) {
	case "tls", "ssl":
		return d.sendTLS(target, data)
	case "udp":
		return d.sendUDP(target, data)
	case "tcp", "":
		return d.sendTCP(target, data)
	default:
		return d.sendTCP(target, data)
	}
}

func (d *DefaultServiceSender) sendTCP(target string, data []byte) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", target, d.timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if len(data) > 0 {
		conn.SetWriteDeadline(time.Now().Add(d.timeout))
		_, err = conn.Write(data)
		if err != nil {
			return nil, err
		}
	}

	conn.SetReadDeadline(time.Now().Add(d.timeout))
	buffer := make([]byte, 10240)
	n, err := conn.Read(buffer)
	if n > 0 {
		return buffer[:n], nil
	}
	if err != nil {
		return nil, err
	}
	return buffer[:n], nil
}

func (d *DefaultServiceSender) sendTLS(target string, data []byte) ([]byte, error) {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: d.timeout}, "tcp", target, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if len(data) > 0 {
		conn.SetWriteDeadline(time.Now().Add(d.timeout))
		_, err = conn.Write(data)
		if err != nil {
			return nil, err
		}
	}

	conn.SetReadDeadline(time.Now().Add(d.timeout))
	buffer := make([]byte, 10240)
	n, err := conn.Read(buffer)
	if n > 0 {
		return buffer[:n], nil
	}
	if err != nil {
		return nil, err
	}
	return buffer[:n], nil
}

func (d *DefaultServiceSender) sendUDP(target string, data []byte) ([]byte, error) {
	conn, err := net.DialTimeout("udp", target, d.timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if len(data) > 0 {
		conn.SetWriteDeadline(time.Now().Add(d.timeout))
		_, err = conn.Write(data)
		if err != nil {
			return nil, err
		}
	}

	readTimeout := d.timeout
	if readTimeout > 200*time.Millisecond {
		readTimeout = 200 * time.Millisecond
	}
	conn.SetReadDeadline(time.Now().Add(readTimeout))

	buffer := make([]byte, 10240)
	n, err := conn.Read(buffer)
	if n > 0 {
		return buffer[:n], nil
	}
	if err != nil {
		return nil, err
	}
	return buffer[:n], nil
}

func (d *DefaultServiceSender) parsePortString(portStr string, defaultNetwork string) (port int, network string) {
	portStr = strings.TrimSpace(portStr)
	network = defaultNetwork

	if strings.HasPrefix(strings.ToUpper(portStr), "U:") {
		portStr = portStr[2:]
		network = "udp"
	}

	portNum, err := strconv.Atoi(portStr)
	if err != nil {
		return 80, network
	}

	return portNum, network
}

type ServiceCallback func(*ServiceResult)

type DefaultHTTPSender struct {
	client *http.Client
}

func NewHTTPSender(timeout time.Duration) http.RoundTripper {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	return &DefaultHTTPSender{
		client: &http.Client{
			Transport: http.DefaultTransport,
			Timeout:   timeout,
		},
	}
}

func (d *DefaultHTTPSender) RoundTrip(req *http.Request) (*http.Response, error) {
	return d.client.Transport.RoundTrip(req)
}
