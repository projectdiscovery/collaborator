// +build linux

package biid

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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

		n, _, err := tcpConn.ReadFrom(data)
		if err != nil {
			continue
		}
		packet := gopacket.NewPacket(data[:n], layers.LayerTypeTCP, gopacket.Default)
		if !checkPacket(packet) {
			continue
		}

		applicationLayer := packet.ApplicationLayer()
		biid = extractbiid(applicationLayer.Payload())
	}
}
