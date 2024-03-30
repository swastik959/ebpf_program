package main

import (
	"log"
	"net"
	"os"
	"strconv"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

/*
#cgo CFLAGS: -I/path/to/c/headers
#cgo LDFLAGS: -L/path/to/c/libraries -lmy_c_library
#include "my_c_library.h"
*/

func main() {
	if len(os.Args) != 3 {
		log.Fatalf("Usage: %s <interface> <port>\n", os.Args[0])
	}

	ifaceName := os.Args[1]
	iface, _ := net.InterfaceByName(ifaceName)

	portStr := os.Args[2]
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		log.Fatalf("Invalid port number: %s\n", portStr)
	}

	specs, err := ebpf.LoadCollectionSpec("xdp_prog.o")
	if err != nil {
		log.Fatalf("Failed to load ebpf collection spec: %v", err)
	}

	coll, err := ebpf.NewCollection(specs)
	if err != nil {
		log.Fatalf("Failed to load eBPF collection: %v", err)
	}
	defer coll.Close()

	prog, ok := coll.Programs["xdp_drop_port"]
	if !ok {
		log.Fatal("Cannot find XDP program in collection")
	}

	bpfMap, ok := coll.Maps["port_map"]
	if !ok {
		log.Fatal("Cannot find map in collection")
	}

	link, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("Failed to attach XDP program: %v", err)
	}
	defer link.Close()

	if err := bpfMap.Put(uint32(0), uint32(port)); err != nil {
		log.Fatalf("Failed to update map: %v", err)
	}

}
