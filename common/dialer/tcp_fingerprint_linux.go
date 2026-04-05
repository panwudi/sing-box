//go:build linux

package dialer

import (
	"syscall"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
)

// tcpFingerprintControl creates a Control callback that sets TCP stack fingerprint
// parameters via setsockopt after socket creation but before connect.
// These parameters affect SYN packet characteristics, making the target see a TCP
// stack matching the specified operating system.
func tcpFingerprintControl(fp *option.TCPFingerprint) control.Func {
	return func(network, address string, conn syscall.RawConn) error {
		return control.Raw(conn, func(fd uintptr) error {
			// Set IP TTL: Windows=128, Unix=64. This is the most critical detection feature.
			if fp.TTL > 0 {
				// IPv4 TTL
				_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, fp.TTL)
				// IPv6 Hop Limit (equivalent to TTL)
				_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, fp.TTL)
			}
			// Set TCP MSS: affects the MSS option in SYN packets.
			if fp.MSS > 0 {
				_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_MAXSEG, fp.MSS)
			}
			// Set TCP Window Clamp: limits the receive window upper bound.
			// TCP_WINDOW_CLAMP = 33 (0x21), not defined in Go's syscall package.
			if fp.WindowClamp > 0 {
				_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, 0x21, fp.WindowClamp)
			}
			return nil
		})
	}
}
