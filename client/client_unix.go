//go:build !windows

package main

import "net"

const icmpProto string = "udp4"
const icmpProtoRaw string = "ip4:icmp"

const commonError string = "Make sure the target IP is reachable"
const commonErrorRaw string = "Make sure you are running with elevated " +
	"privileges and the target IP is reachable"

// resolveAddr resolves the target IP address for the appropriate network type (file transfers)
func resolveAddr(targetIP string) (net.Addr, error) {
	return net.ResolveUDPAddr(icmpProto, targetIP+":0")
}

// resolveAddrRaw resolves the target IP address for raw ICMP (sweep mode)
func resolveAddrRaw(targetIP string) (net.Addr, error) {
	return net.ResolveIPAddr(icmpProtoRaw, targetIP)
}
