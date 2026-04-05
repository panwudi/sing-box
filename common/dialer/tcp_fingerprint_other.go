//go:build !linux

package dialer

import (
	"syscall"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
)

// tcpFingerprintControl is a stub for non-Linux platforms.
// TCP fingerprint functionality only takes effect on Linux servers (exit nodes).
func tcpFingerprintControl(fp *option.TCPFingerprint) control.Func {
	return func(network, address string, conn syscall.RawConn) error {
		return nil
	}
}
