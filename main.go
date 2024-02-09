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
			{"eth.type": eth["eth.type"].(string)}, {"ip.version": ip["ip.version"].(string)},
			{"ip.hdr_len": ip["ip.hdr_len"].(string)}, {"ip.dsfield": ip["ip.dsfield"].(string)},
			{"ip.len": ip["ip.len"].(string)}, {"ip.id": ip["ip.id"].(string)}, {"ip.flags": ip["ip.flags"].(string)},
			{"ip.frag_offset": ip["ip.frag_offset"].(string)}, {"ip.ttl": ip["ip.ttl"].(string)},
			{"ip.proto": ip["ip.proto"].(string)}, {"ip.checksum": ip["ip.checksum"].(string)},
			{"ip.src": ip["ip.src"].(string)}, {"ip.dst": ip["ip.dst"].(string)}}

		switch *sorted {
		case "icmp":
			icmp, _ := frameData.WsSource.Layers["icmp"].(map[string]interface{})
			order = append(order,
				map[string]interface{}{"icmp.type": icmp["icmp.type"].(string)}, map[string]interface{}{"icmp.code": icmp["icmp.code"].(string)},
				map[string]interface{}{"icmp.checksum": icmp["icmp.checksum"].(string)}, map[string]interface{}{"icmp.ident": icmp["icmp.ident"].(string)},
				map[string]interface{}{"icmp.seq": icmp["icmp.seq"].(string)})
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

	err = t.Execute(&buf, &newMap)
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
