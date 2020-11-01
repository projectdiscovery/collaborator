package collaborator

import (
	"bytes"
	"fmt"
	"time"
)

const (
	privateKeyPattern     = "burpresults?biid="
	snaplen               = 1600
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
