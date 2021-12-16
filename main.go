package main

import (
	"encoding/binary"
	"flag"
	"log"
	"strings"

	"github.com/cilium/ebpf"
	"inet.af/netaddr"
)

func main() {

	var daddr string
	var bpfMap int
	flag.StringVar(&daddr, "d", "", "ip addresses to drop, separated by ','")
	flag.IntVar(&bpfMap, "m", 0, "the id of the bpf map(filter_daddrs)")
	flag.Parse()

	var ips []netaddr.IP
	addrs := strings.FieldsFunc(daddr, func(r rune) bool { return r == ',' })
	for _, addr := range addrs {
		ip, err := netaddr.ParseIP(addr)
		if err != nil {
			log.Fatalf("%s is not a valid IPv4 address", ip)
		}

		ips = append(ips, ip)
	}
	if len(ips) == 0 {
		log.Fatalf("no ip address(es) to be dropped")
	}

	m, err := ebpf.NewMapFromID(ebpf.MapID(bpfMap))
	if err != nil {
		log.Fatalf("bpf map(%d) not found, err: %v", bpfMap, err)
	}

	val := uint8(1)
	for _, ip := range ips {
		_ip := ip.As4()
		ipval := binary.LittleEndian.Uint32(_ip[:])
		if err := m.Update(ipval, val, ebpf.UpdateAny); err != nil {
			log.Fatalf("failed to upsert data to bpf map(%d), err: %v", bpfMap, err)
		}
	}

	log.Printf("%s can't be pinged", daddr)
}
