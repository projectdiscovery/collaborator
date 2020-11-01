package collaborator

import (
	"bytes"
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	privateKeyPattern     = "burpresults?biid="
	snaplen               = 1600
	dstPort               = 80
	ebpFilter             = "tcp and dst port 80"
	externalIpProbeTarget = "8.8.8.8"
)

func extractbiid(data []byte) string {
	// just crawl without decoding
	begin := bytes.Index(data, []byte(privateKeyPattern))
	if begin > 0 {
		begin += len(privateKeyPattern)
		end := bytes.Index(data[begin:], []byte(" "))
		if end > 0 {
			return string(data[begin : begin+end])
		}
	}

	return ""
}

func Intercept(timeout time.Duration) (string, error) {
	c1 := make(chan string, 1)
	var stop bool

	go func() {
		c1 <- dumpBIID(&stop)
	}()

	select {
	case biid := <-c1:
		return biid, nil
	case <-time.After(timeout):
		stop = true
		return "", fmt.Errorf("Timeout")
	}
}

func checkPacket(packet gopacket.Packet) bool {
	if packet == nil {
		return false
	}
	if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP || packet.ApplicationLayer() == nil {
		return false
	}

	tcp, ok := packet.TransportLayer().(*layers.TCP)
	if !ok {
		return false
	}
	if tcp.DstPort != layers.TCPPort(dstPort) {
		return false
	}

	return true
}
