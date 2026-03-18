package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/mjwhitta/cli"
	"golang.org/x/net/icmp"
)

var flags struct {
	outDir    string
	sweepMode bool
	timeout   int
}

// Error to handle the user entering CTRL+c
var errStop error = errors.New("stop")

// extractPayload extracts the data payload from various ICMP message types
func extractPayload(msg *icmp.Message) ([]byte, bool) {
	switch body := msg.Body.(type) {
	case *icmp.Echo:
		return body.Data, true
	case *icmp.TimeExceeded:
		return body.Data, true
	case *icmp.DstUnreach:
		return body.Data, true
	case *icmp.PacketTooBig:
		return body.Data, true
	case *icmp.ParamProb:
		return body.Data, true
	case *icmp.RawBody:
		// For ICMP types without explicit parsers (Timestamp, Router Advertisement,
		// Redirect, Information Request, Address Mask Request, etc.)
		return body.Data, true
	default:
		// Unknown message body type
		return nil, false
	}
}

func init() {
	cli.Flag(
		&flags.outDir,
		"o",
		"outDir",
		".",
		"Directory to write received files",
	)
	cli.Flag(
		&flags.sweepMode,
		"s",
		"sweep",
		false,
		"Run in sweep mode to listen for a sweep of packets with all ICMP "+
			"types, to see what gets through (see client.go for more info)",
	)
	cli.Flag(
		&flags.timeout,
		"t",
		"timeout",
		30,
		"Seconds to wait after first block before timing out",
	)
	cli.Parse()
}

func listenForSweep() {
	var (
		conn  *icmp.PacketConn
		err   error
		sigCh chan os.Signal
		stop  bool
	)

	conn, err = icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Error: %v\n", err)
		fmt.Fprintf(os.Stderr, "[!] Make sure you are running with elevated privileges\n")
		return
	}
	defer conn.Close()

	// Create a channel to handle the user entering CTRL+c (os.Interrupt)
	sigCh = make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	defer signal.Stop(sigCh)

	// Check for CTRL+c
	go func() {
		<-sigCh
		stop = true
		// If CTRL+c is entered, set the timeout to now
		conn.SetReadDeadline(time.Now())
	}()

	for {
		err = recvPacket(conn, &stop)
		if err != nil {
			if errors.Is(err, errStop) {
				break
			}
			fmt.Fprintf(os.Stderr, "[!] Error: %v\n", err)
		}
	}
}

func main() {

	if flags.sweepMode {
		fmt.Printf(
			"[*] Listening for all ICMP sweep...\n",
		)
		listenForSweep()
		return
	}
	fmt.Printf(
		"[*] Listening for files on all ICMP types (saving to %s)...\n",
		flags.outDir,
	)

	startReceiving()

	fmt.Println("[*] WOOOOOOOO! Have a nice day")
}

func recvFile(conn *icmp.PacketConn, stop *bool) error {
	var (
		blockNum    uint32
		blocks      map[uint32][]byte
		buf         []byte
		err         error
		f           *os.File
		filename    string
		i           uint32
		missing     []uint32
		msg         *icmp.Message
		n           int
		ok          bool
		outPath     string
		payload     []byte
		received    int
		seen        map[uint32]bool
		totalBlocks uint32
	)

	// Clear any deadline left over from the previous file so we
	// wait indefinitely for the next file's block 0
	err = conn.SetReadDeadline(time.Time{})
	if err != nil {
		return err
	}

	blocks = make(map[uint32][]byte)
	buf = make([]byte, 65536)
	seen = make(map[uint32]bool)

	for {
		n, _, err = conn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				fmt.Println()
				// First check if "timeout" is due to CTRL+c (see the
				// check for CTRL+c above)
				if *stop {
					return errStop
				}
				// Otherwise, this is a true timeout
				fmt.Printf(
					"[!] Timeout after %d seconds\n",
					flags.timeout,
				)
				break
			}
			return err
		}

		msg, err = icmp.ParseMessage(1, buf[:n])
		if err != nil {
			continue
		}

		// Extract payload based on ICMP message type
		payload, ok = extractPayload(msg)
		if !ok || len(payload) < 8 {
			continue
		}

		// Packet format: [blockNum uint32][totalBlocks uint32][data...]
		// Block 0 is the filename packet; blocks 1..N are file data.
		blockNum = binary.BigEndian.Uint32(payload[0:4])

		// Check for duplicate packets
		if seen[blockNum] {
			continue
		}
		seen[blockNum] = true

		// Block 0 is just the file name
		if blockNum == 0 {
			filename = filepath.ToSlash(string(payload[8:]))
			totalBlocks = binary.BigEndian.Uint32(payload[4:8])
			fmt.Printf("[*] Incoming file: %s (via ICMP type %v)\n", filename, msg.Type)

			// The timeout timer is not started until the first packet
			// of a file is received
			err = conn.SetReadDeadline(
				time.Now().Add(
					time.Duration(flags.timeout) * time.Second,
				),
			)
			if err != nil {
				return err
			}
			continue
		}

		// Ignore data blocks if we haven't received the filename yet
		if filename == "" {
			continue
		}

		data := make([]byte, len(payload)-8)
		copy(data, payload[8:])
		blocks[blockNum] = data
		received++

		fmt.Printf(
			"\r[*] Received block %d of %d",
			blockNum, totalBlocks,
		)

		if uint32(received) == totalBlocks {
			fmt.Println()
			break
		}
	}

	if filename == "" {
		return fmt.Errorf("no filename received")
	}

	// Get rid of any `..`s in the path (e.g., to prevent dir traversal)
	for strings.HasPrefix(filename, "../") {
		filename = strings.TrimPrefix(filename, "../")
	}

	outPath = filepath.Join(flags.outDir, filename)

	// Create the dir(s), if necessary
	err = os.MkdirAll(filepath.Dir(outPath), 0o755)
	if err != nil {
		return err
	}

	f, err = os.Create(outPath)
	if err != nil {
		return err
	}
	defer f.Close()

	// Check for missing blocks (e.g., due to a timeout)
	// If the current block is not missing, write it to file
	for i = 1; i <= totalBlocks; i++ {
		_, ok = blocks[i]
		if !ok {
			missing = append(missing, i)
			continue
		}

		_, err = f.Write(blocks[i])
		if err != nil {
			return err
		}
	}

	if len(missing) > 0 {
		fmt.Printf("[!] Missing blocks: %v\n", missing)
		return fmt.Errorf(
			"transfer incomplete: %d of %d blocks missing",
			len(missing), totalBlocks,
		)
	}

	fmt.Printf("[*] Saved to: %s\n", outPath)
	return nil
}

func recvPacket(conn *icmp.PacketConn, stop *bool) error {
	var (
		buf []byte
		err error
		msg *icmp.Message
		n   int
	)

	buf = make([]byte, 65536)

	for {
		n, _, err = conn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				if *stop {
					return errStop
				}
				continue
			}
			return err
		}

		msg, err = icmp.ParseMessage(1, buf[:n])
		if err != nil {
			continue
		}

		// Report the ICMP packet type
		fmt.Printf(
			"[*] Received ICMP packet of type: %d (%v)\n",
			msg.Type,
			msg.Type,
		)
	}
}

func startReceiving() {
	var (
		conn  *icmp.PacketConn
		err   error
		sigCh chan os.Signal
		stop  bool
	)

	conn, err = icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Error: %v\n", err)
		fmt.Fprintf(os.Stderr, "[!] Make sure you are running with elevated privileges\n")
		return
	}
	defer conn.Close()

	// Create a channel to handle the user entering CTRL+c (os.Interrupt)
	sigCh = make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	defer signal.Stop(sigCh)

	// Check for CTRL+c
	go func() {
		<-sigCh
		stop = true
		// If CTRL+c is entered, set the timeout to now
		conn.SetReadDeadline(time.Now())
	}()

	for {
		err = recvFile(conn, &stop)
		if err != nil {
			// recvFile returns errStop when the user enters CTRL+c
			if errors.Is(err, errStop) {
				return
			}
			fmt.Fprintf(os.Stderr, "[!] Error: %v\n", err)
		}
	}
}
