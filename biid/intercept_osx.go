// +build darwin

package collaborator

import (
	"fmt"
	"net"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func dumpBIID(stop *bool) string {
	var biid string

	sourceIP, err := GetSourceIP(net.ParseIP(externalIpProbeTarget))
	if err != nil {
		return ""
	}
	networkInterface, err := GetInterfaceFromIP(sourceIP)
	if err != nil {
		return ""
	}

	handle, err := pcap.OpenLive(networkInterface.Name, snaplen, true, pcap.BlockForever)
	if err != nil {
		return ""
	}
	defer handle.Close()

	err = handle.SetBPFFilter(ebpFilter)
	if err != nil {
		return ""
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	for {
		if *stop {
			return biid
		}
		if biid != "" {
			return biid
		}
		select {
		case packet := <-packets:
			if !checkPacket(packet) {
				continue
			}

			applicationLayer := packet.ApplicationLayer()
			biid = extractbiid(applicationLayer.Payload())
		}
	}
}

// Code from naabu
func GetSourceIP(dstip net.IP) (net.IP, error) {
	serverAddr, err := net.ResolveUDPAddr("udp", dstip.String()+":12345")
	if err != nil {
		return nil, err
	}

	con, dialUpErr := net.DialUDP("udp", nil, serverAddr)
	if dialUpErr != nil {
		return nil, dialUpErr
	}

	defer con.Close()
	if udpaddr, ok := con.LocalAddr().(*net.UDPAddr); ok {
		return udpaddr.IP, nil
	}

	return nil, nil
}

func GetInterfaceFromIP(ip net.IP) (*net.Interface, error) {
	address := ip.String()

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, i := range interfaces {
		byNameInterface, err := net.InterfaceByName(i.Name)
		if err != nil {
			return nil, err
		}

		addresses, err := byNameInterface.Addrs()
		if err != nil {
			return nil, err
		}

		for _, v := range addresses {
			if strings.HasPrefix(v.String(), address+"/") {
				return byNameInterface, nil
			}
		}
	}

	return nil, fmt.Errorf("no interface found for ip %s", address)
}
