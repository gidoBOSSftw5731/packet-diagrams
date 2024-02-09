package main

import (
	"bytes"
	"flag"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"text/template"

	"github.com/randolphcyg/gowireshark"
)

var (
	pcapFile     *string = flag.String("pcap", "test.pcap", "pcap file to read")
	packetNumber *int    = flag.Int("packet", 0, "packet number to read")
)

func main() {
	// parse flags
	flag.Parse()

	// read frame in to buffer
	frameData, err := gowireshark.GetSpecificFrameProtoTreeInJson(*pcapFile, *packetNumber, false, false)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%#v\n\n", frameData.WsSource.Layers["ip"])

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
				// check if v is in hex colon notation
				// if so, return the number of bytes
				// This is a stupid implementation but tonight
				// is not the night for doing this properly
				if len(v.(string)) == 17 {
					if v.(string)[2] == ':' {
						return 6
					}
				}

				// check if it's a number
				// if so, return 1 byte
				if _, err := strconv.ParseInt(v.(string), 10, 64); err == nil {
					return 1
				}

				if len(v.(string)) < 2 {
					return -1
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

			}
			return -1
		},
		"fieldchange": fieldchange,
	}

	newMap := make(map[string]interface{})
	//newMap["1"] = frameData.WsSource.Layers["frame"]
	newMap["2"] = frameData.WsSource.Layers["eth"]
	newMap["3"] = frameData.WsSource.Layers["ip"]
	newMap["4"] = frameData.WsSource.Layers["icmp"]

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
		return "Protocol"
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
	}
	return v.(string)

}
