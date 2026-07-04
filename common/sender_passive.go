//go:build passive_only
// +build passive_only

package common

import "time"

func NewServiceSender(timeout time.Duration) ServiceSender { return nil }
