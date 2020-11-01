// +build linux

package collaborator

import (
	"fmt"
	"net"

	"github.com/phayes/freeport"
)

// requires root
func dumpBIID(stop *bool) string {
	var biid string
	rawPort, err := freeport.GetFreePort()
	if err != nil {
		return ""
	}

	tcpConn, err := net.ListenIP("ip4:tcp", &net.IPAddr{IP: net.ParseIP(fmt.Sprintf("0.0.0.0:%d", rawPort))})
	if err != nil {
		return ""
	}
	defer tcpConn.Close()
	data := make([]byte, 4096)
	for {
		if biid != "" {
			return biid
		}
		if *stop {
			return ""
		}

		tcpConn.ReadFrom(data)
		biid = extractbiid(data)
	}
}
