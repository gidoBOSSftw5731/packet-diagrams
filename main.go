package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"text/template"

	"github.com/randolphcyg/gowireshark"
)

var (
	pcapFile     *string = flag.String("pcap", "test.pcap", "pcap file to read")
	packetNumber *int    = flag.Int("packet", 0, "packet number to read")
	sorted       *string = flag.String("sort", "", "sort fields automatically based on protocol")
)

type PacketTemplate struct {
	PacketData             map[string]interface{}
	FieldDescriptionString string
}

func main() {
	// parse flags
	flag.Parse()

	// read frame in to buffer
	frameData, err := gowireshark.GetSpecificFrameProtoTreeInJson(*pcapFile, *packetNumber, false, false)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%#v\n\n", frameData.WsSource.Layers)

	// load text template from packet.html
	// read packet.html.gtpl into string
	tmplFile, err := os.ReadFile("packet.html.gtpl")
	if err != nil {
		panic(err)
	}

	funcMap := template.FuncMap{
		"typeof": func(v interface{}) string {
			return fmt.Sprintf("%T", v)
		},
		"sizeof": func(v interface{}) int {

			switch fmt.Sprintf("%T", v) {
			case "string":
				// check if it's a number
				// if so, return 1 byte
				if _, err := strconv.ParseInt(v.(string), 10, 64); err == nil {
					return 1
				}

				if len(v.(string)) < 2 {
					return -1
				}

				// check if v is in hex colon notation
				// if so, return the number of bytes
				// This is a stupid implementation but tonight
				// is not the night for doing this properly
				if v.(string)[2] == ':' {
					return (len(v.(string)) + 1) / 3
				}

				// check if v is an IPv4 address
				// if so, return the number of bytes
				// check format with regex
				ipmatch, _ := regexp.Match(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`, []byte(v.(string)))
				if ipmatch {
					return 4
				}

				if v.(string)[0] == '0' && v.(string)[1] == 'x' {
					return (len(v.(string)) - 2) / 2
				}

				return len(v.(string))

			}
			return -1
		},
		"fieldchange": fieldchange,
	}

	newMap := make(map[string]interface{})
	//newMap["1"] = frameData.WsSource.Layers["frame"]
	newMap["2"] = frameData.WsSource.Layers["eth"]
	if frameData.WsSource.Layers["eth"].(map[string]interface{})["eth.type"].(string) == "0x0800" {
		newMap["3"] = frameData.WsSource.Layers["ip"]
		// check if ICMP
		if frameData.WsSource.Layers["ip"].(map[string]interface{})["ip.proto"].(string) == "1" {
			newMap["4"] = frameData.WsSource.Layers["icmp"]
			// check if data exists
			if _, ok := frameData.WsSource.Layers["icmp"].(map[string]interface{})["data"]; ok {
				newMap["5"] = map[string]interface{}{
					"Data": hexToASCII(
						frameData.WsSource.Layers["icmp"].(map[string]interface{})["data"].(map[string]interface{})["data.data"].(string)),
				}
			}
		}
		// check if UDP
	}
	// check if arp
	if frameData.WsSource.Layers["eth"].(map[string]interface{})["eth.type"].(string) == "0x0806" {
		newMap["3"] = frameData.WsSource.Layers["arp"]
	}

	// check if sort is set
	// yes this does mean that everything above is redundant but I don't want another nested if
	// this code is *really bad* but it's not meant to be maintained.
	if *sorted != "" {
		newMap = make(map[string]interface{})
		eth, _ := frameData.WsSource.Layers["eth"].(map[string]interface{})
		ip, _ := frameData.WsSource.Layers["ip"].(map[string]interface{})
		order := []map[string]interface{}{{"eth.dst": eth["eth.dst"].(string)}, {"eth.src": eth["eth.src"].(string)},
			{"eth.type": eth["eth.type"].(string)},
		}
		// check for eth padding
		if _, ok := eth["eth.padding"]; ok {
			order = append(order, map[string]interface{}{"eth.padding": eth["eth.padding"].(string)})
		}
		// check for IP
		if _, ok := frameData.WsSource.Layers["ip"]; ok {
			order = append(order, map[string]interface{}{"ip.version": ip["ip.version"].(string)},
				map[string]interface{}{"ip.hdr_len": ip["ip.hdr_len"].(string)}, map[string]interface{}{"ip.dsfield": ip["ip.dsfield"].(string)},
				map[string]interface{}{"ip.len": ip["ip.len"].(string)}, map[string]interface{}{"ip.id": ip["ip.id"].(string)},
				map[string]interface{}{"ip.flags": ip["ip.flags"].(string)}, map[string]interface{}{"ip.frag_offset": ip["ip.frag_offset"].(string)},
				map[string]interface{}{"ip.ttl": ip["ip.ttl"].(string)}, map[string]interface{}{"ip.proto": ip["ip.proto"].(string)},
				map[string]interface{}{"ip.checksum": ip["ip.checksum"].(string)}, map[string]interface{}{"ip.src": ip["ip.src"].(string)},
				map[string]interface{}{"ip.dst": ip["ip.dst"].(string)})
		}
		switch *sorted {
		case "icmp":
			icmp, _ := frameData.WsSource.Layers["icmp"].(map[string]interface{})
			order = append(order,
				map[string]interface{}{"icmp.type": icmp["icmp.type"].(string)}, map[string]interface{}{"icmp.code": icmp["icmp.code"].(string)},
				map[string]interface{}{"icmp.checksum": icmp["icmp.checksum"].(string)}, map[string]interface{}{"icmp.ident": icmp["icmp.ident"].(string)},
				map[string]interface{}{"icmp.seq": icmp["icmp.seq"].(string)})
			if _, ok := icmp["data"]; ok {
				order = append(order, map[string]interface{}{"Data": hexToASCII(
					frameData.WsSource.Layers["icmp"].(map[string]interface{})["data"].(map[string]interface{})["data.data"].(string))})
			}

		case "arp":
			arp, _ := frameData.WsSource.Layers["arp"].(map[string]interface{})
			order = append(order,
				map[string]interface{}{"arp.hw.type": arp["arp.hw.type"].(string)}, map[string]interface{}{"arp.proto.type": arp["arp.proto.type"].(string)},
				map[string]interface{}{"arp.hw.size": arp["arp.hw.size"].(string)}, map[string]interface{}{"arp.proto.size": arp["arp.proto.size"].(string)},
				map[string]interface{}{"arp.opcode": arp["arp.opcode"].(string)}, map[string]interface{}{"arp.src.hw_mac": arp["arp.src.hw_mac"].(string)},
				map[string]interface{}{"arp.src.proto_ipv4": arp["arp.src.proto_ipv4"].(string)},
				map[string]interface{}{"arp.dst.hw_mac": arp["arp.dst.hw_mac"].(string)},
				map[string]interface{}{"arp.dst.proto_ipv4": arp["arp.dst.proto_ipv4"].(string)},
			)
		default:
			panic("Invalid sort")
		}

		for k, v := range order {
			newMap[fmt.Sprintf("%5v", k)] = v
		}

	}

	t, err := template.New("packet").Funcs(funcMap).Parse(string(tmplFile))
	if err != nil {
		panic(err)
	}
	var buf bytes.Buffer

	fieldDescs := ""
	for _, entry := range newMap {
		for name, _ := range entry.(map[string]interface{}) {
			fieldDescs += fmt.Sprintf("%v: %v\n<br>", fieldchange(name), FieldDescriptions[name])
		}
	}

	err = t.Execute(&buf, &PacketTemplate{PacketData: newMap, FieldDescriptionString: fieldDescs})
	if err != nil {
		panic(err)
	}

	// create http server and serve the html from buf
	err = http.ListenAndServe(":8080", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(buf.Bytes())
	}))

}

func fieldchange(v interface{}) string {
	// check if stringt
	switch fmt.Sprintf("%T", v) {
	case "string":
	default:
		return ""
	}
	switch v.(string) {
	case "eth.dst":
		return "Destination MAC"
	case "eth.src":
		return "Source MAC"
	case "eth.type":
		return "Ethernet Type"
	case "ip.src":
		return "Source IP"
	case "ip.dst":
		return "Destination IP"
	case "ip.proto":
		return "Layer 3 Protocol"
	case "ip.ttl":
		return "TTL"
	case "ip.hdr_len":
		return "IP Header Length"
	case "ip.dsfield":
		return "Differentiated Services Field"
	case "ip.len":
		return "IP Length"
	case "ip.id":
		return "IP ID"
	case "ip.flags":
		return "IP Flags"
	case "ip.frag_offset":
		return "Fragment Offset"
	case "ip.checksum":
		return "IP Checksum"
	case "ip.version":
		return "IP Version"
	case "icmp.type":
		return "ICMP Type"
	case "icmp.code":
		return "ICMP Code"
	case "icmp.checksum":
		return "ICMP Checksum"
	case "icmp.ident":
		return "ICMP Identifier"
	case "icmp.seq":
		return "ICMP Sequence Number"
	case "icmp.data":
		return "ICMP Data"
	case "arp.hw.type":
		return "ARP Hardware Type"
	case "arp.proto.type":
		return "ARP Protocol Type"
	case "arp.hw.size":
		return "ARP Hardware Size"
	case "arp.proto.size":
		return "ARP Protocol Size"
	case "arp.opcode":
		return "ARP Opcode"
	case "arp.src.hw_mac":
		return "ARP Source MAC"
	case "arp.src.proto_ipv4":
		return "ARP Source IP"
	case "arp.dst.hw_mac":
		return "ARP Target MAC"
	case "arp.dst.proto_ipv4":
		return "ARP Target IP"
	}
	return v.(string)

}

func hexToASCII(hexString string) string {
	hexValues := strings.Split(hexString, ":")

	/*
		// I thought this was a good idea but it messes with the count...
		// I'll let it just be empty, whatever
		allNullMatch, _ := regexp.Match(`^(?:00:)+00$`, []byte(hexString))
		if allNullMatch {
			return "null"
		}
	*/

	var asciiBytes []byte
	for _, hexVal := range hexValues {
		decodedByte, err := hex.DecodeString(hexVal)
		if err != nil {
			return ""
		}

		asciiBytes = append(asciiBytes, decodedByte...)
	}

	return string(asciiBytes)
}

// FieldDescriptions contains descriptions of fields in a packet
var FieldDescriptions = map[string]string{
	"eth.dst":            "The Destination MAC address is the address that the frame is being sent to",
	"eth.src":            "The Source MAC address is the address that the frame is being sent from",
	"eth.type":           "The Ethernet Type is the type of frame being sent, like an IP packet or ARP packet",
	"ip.src":             "The Source IP address is the address that the packet is being sent from",
	"ip.dst":             "The Destination IP address is the address that the packet is being sent to",
	"ip.proto":           "The Layer 3 Protocol is the protocol that the packet is using, usually TCP, UDP, or ICMP",
	"ip.ttl":             "The Time to Live is the number of hops the packet can take before being dropped. This is implemented to prevent routing loops from causing issues",
	"ip.hdr_len":         "The length of the IP Header",
	"ip.dsfield":         "The Differentiated Services Field is used to differentiate between different types of traffic, usually for Quality of Service purposes",
	"ip.len":             "The length of the IP packet",
	"ip.id":              "A unique identifier for the packet",
	"ip.flags":           "The flags for the IP packet which help identify some edge cases (like fragmentation)",
	"ip.frag_offset":     "The fragment offset for the IP packet which helps reconstruct fragmented packets",
	"ip.checksum":        "A checksum of the header to verify the integrity of the header",
	"ip.version":         "The version of the IP protocol being used",
	"icmp.type":          "The type of ICMP packet being sent, like an echo request or echo reply",
	"icmp.code":          "The code for an ICMP packet is used to determine some more advanced information about the packet, like who can recieve it",
	"icmp.checksum":      "A checksum of the ICMP Packet header to verify the integrity of the header",
	"icmp.ident":         "Helps identify the ICMP packet, especially for echo requests and replies",
	"icmp.seq":           "The sequence number for the ICMP packet which helps identify the order of packets",
	"icmp.data":          "The data for the ICMP packet, usually just the alphabet though there are some uses of this field",
	"Data":               "The data for the ICMP packet, usually just the alphabet though there are some uses of this field",
	"arp.hw.type":        "The hardware type for the ARP packet",
	"arp.proto.type":     "The hardware type is almost always Ethernet, but it can be something else like Infiniband or Token Ring",
	"arp.hw.size":        "This is the length of the hardware address, usually 6 bytes for Ethernet",
	"arp.proto.size":     "This is the length of the protocol address, usually 4 bytes for IPv4",
	"arp.opcode":         "The opcode for the ARP packet, if it's a request or a reply",
	"arp.src.hw_mac":     "The source hardware address for the ARP packet",
	"arp.src.proto_ipv4": "The source protocol address for the ARP packet",
	"arp.dst.hw_mac":     "The destination hardware address for the ARP packet",
	"arp.dst.proto_ipv4": "The destination protocol address for the ARP packet",
}
