package common

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// Service指纹检测的Sender抽象
type ServiceSender interface {
	Send(host string, port int, data []byte, network string) ([]byte, error)
}

// DefaultServiceSender 默认的ServiceSender实现
type DefaultServiceSender struct {
	timeout time.Duration
}

// NewServiceSender 创建默认的ServiceSender
func NewServiceSender(timeout time.Duration) ServiceSender {
	if timeout <= 0 {
		timeout = 5 * time.Second // 默认5秒超时
	}
	return &DefaultServiceSender{
		timeout: timeout,
	}
}

// Send 实现ServiceSender接口，支持TCP、UDP、TLS协议
func (d *DefaultServiceSender) Send(host string, port int, data []byte, network string) ([]byte, error) {
	target := fmt.Sprintf("%s:%d", host, port)

	// 根据network参数选择协议
	switch strings.ToLower(network) {
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

// sendTCP 发送TCP数据
func (d *DefaultServiceSender) sendTCP(target string, data []byte) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", target, d.timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// 发送数据
	if len(data) > 0 {
		// 设置写超时
		conn.SetWriteDeadline(time.Now().Add(d.timeout))
		_, err = conn.Write(data)
		if err != nil {
			return nil, err
		}
	}

	// 设置较短的读超时，优化响应速度
	readTimeout := d.timeout
	if readTimeout > 500*time.Millisecond {
		readTimeout = 500 * time.Millisecond // 最多等待500ms读取响应
	}
	conn.SetReadDeadline(time.Now().Add(readTimeout))

	// 读取响应
	buffer := make([]byte, 10240)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}

	return buffer[:n], nil
}

// sendTLS 发送TLS数据
func (d *DefaultServiceSender) sendTLS(target string, data []byte) ([]byte, error) {
	conn, err := tls.DialWithDialer(&net.Dialer{
		Timeout: d.timeout,
	}, "tcp", target, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// 发送数据
	if len(data) > 0 {
		// 设置写超时
		conn.SetWriteDeadline(time.Now().Add(d.timeout))
		_, err = conn.Write(data)
		if err != nil {
			return nil, err
		}
	}

	// 设置较短的读超时，优化响应速度
	readTimeout := d.timeout
	if readTimeout > 500*time.Millisecond {
		readTimeout = 500 * time.Millisecond
	}
	conn.SetReadDeadline(time.Now().Add(readTimeout))

	// 读取响应
	buffer := make([]byte, 10240)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}

	return buffer[:n], nil
}

// sendUDP 发送UDP数据
func (d *DefaultServiceSender) sendUDP(target string, data []byte) ([]byte, error) {
	conn, err := net.DialTimeout("udp", target, d.timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// 发送数据
	if len(data) > 0 {
		// 设置写超时
		conn.SetWriteDeadline(time.Now().Add(d.timeout))
		_, err = conn.Write(data)
		if err != nil {
			return nil, err
		}
	}

	// UDP通常响应更快，设置更短的读超时
	readTimeout := d.timeout
	if readTimeout > 200*time.Millisecond {
		readTimeout = 200 * time.Millisecond // UDP最多等待200ms
	}
	conn.SetReadDeadline(time.Now().Add(readTimeout))

	// 读取响应
	buffer := make([]byte, 10240)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}

	return buffer[:n], nil
}

// Service指纹检测的回调函数
type ServiceCallback func(*ServiceResult)
