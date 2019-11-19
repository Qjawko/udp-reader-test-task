package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"log"
)

var (
	pcapFile string = "capture-Bridge0-May 24 12-50-28.pcapng"
	handle   *pcap.Handle
	udpHandle *pcap.Handle
	err      error
	filter   string = "udp"
)

func main() {
	handle, err = pcap.OpenOffline(pcapFile)
	if err != nil {
		log.Fatal(err)
	}

	packetSrc := gopacket.NewPacketSource(handle, handle.LinkType())
	countOfPackets := 0
	for range packetSrc.Packets() {
		countOfPackets++
	}
	fmt.Printf("total number of packets = %d\n", countOfPackets)
	handle.Close()

	udpHandle, err = pcap.OpenOffline(pcapFile)
	if err != nil {
		log.Fatal(err)
	}

	err = udpHandle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}
	defer udpHandle.Close()

	packetUdpSrc := gopacket.NewPacketSource(udpHandle, udpHandle.LinkType())
	countOfUdpPackets := 0
	lengthOfUdpPackets := 0
	for p := range packetUdpSrc.Packets() {
		countOfUdpPackets++
		lengthOfUdpPackets += len(p.Data())
	}

	fmt.Printf("total number of UDP packets = %d\n", countOfUdpPackets)
	fmt.Printf("avg length of UDP packets = %d\n", lengthOfUdpPackets/countOfUdpPackets)
}
