package main

import (
	"flag"
	"fmt"

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
	frameData, err := gowireshark.GetSpecificFrameProtoTreeInJson(*pcapFile, *packetNumber, true, true)
	if err != nil {
		panic(err)
	}

	colSrc := frameData.WsSource.Layers["_ws.col"]
	col, err := gowireshark.UnmarshalWsCol(colSrc)
	if err != nil {
		fmt.Println(err)
	}

	frameSrc := frameData.WsSource.Layers["frame"]
	frame, err := gowireshark.UnmarshalFrame(frameSrc)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println("# Frame index:", col.Num)
	fmt.Println("## WsIndex:", frameData.WsIndex)
	fmt.Println("## Offset:", frameData.Offset)
	fmt.Println("## Hex:", frameData.Hex)
	fmt.Println("## Ascii:", frameData.Ascii)

	fmt.Println("【layer _ws.col】:", col)
	fmt.Println("【layer frame】:", frame)
}
