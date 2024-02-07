package main

import (
	"flag"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	pcapFile     *string = flag.String("pcap", "test.pcap", "pcap file to read")
	packetNumber *int    = flag.Int("packet", 0, "packet number to read")
)

func main() {
	// parse flags
	flag.Parse()

	// read pcap file
	pcapHandler, err := pcap.OpenOffline(*pcapFile)
	if err != nil {
		panic(err)
	}
	defer pcapHandler.Close()
	packetSource := gopacket.NewPacketSource(pcapHandler, pcapHandler.LinkType())
	for i := 0; i < *packetNumber-1; i++ {
		_, err := packetSource.NextPacket()
		if err != nil {
			panic(err)
		}

	}
	pkt, err := packetSource.NextPacket()
	if err != nil {
		panic(err)
	}
	fmt.Println(gopacket.LayerDump(pkt.Layers()[2]))
}

func decodeLayer2(data []byte) (map[string]interface{}, error) {
	decodedFields := make(map[string]interface{})

	// Parse header based on known Layer 2 protocol
	ethLayer := layers.Ethernet{}
	err := ethLayer.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
	if err != nil {
		panic(err)
	}

	decodedFields["Protocol"] = ethLayer.EthernetType.String()
	decodedFields["Destination MAC"] = ethLayer.DstMAC.String()
	decodedFields["Source MAC"] = ethLayer.SrcMAC.String()
	// Add more fields specific to Ethernet header

	// Add payload information if applicable
	payload := data[ethLayer.LayerType():]
	if len(payload) > 0 {
		decodedFields["Payload"] = payload
	}

	return decodedFields, err
}
