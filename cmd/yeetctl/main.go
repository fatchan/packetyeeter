package main

import (
	"PacketYeeter/pkg/collector/ebpf"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
)

const defaultSocketPath = "/var/run/packetyeeter-collector.sock"

var (
	SocketPath string
	Command    string
)

type allowlistEntry struct {
	CIDR    string `json:"cidr"`
	Dynamic bool   `json:"dynamic"`
}

type allowlistResponse struct {
	Status  string           `json:"status"`
	Total   int              `json:"total"`
	Dynamic int              `json:"dynamic"`
	Static  int              `json:"static"`
	Entries []allowlistEntry `json:"entries"`
}

func main() {
	flag.StringVar(&SocketPath, "sock", defaultSocketPath, "Path to PacketYeeter collector socket")
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		fmt.Println("Usage: yeetctl [options] <command>")
		fmt.Println("Commands:")
		fmt.Println("  list       - List blocked IPs")
		fmt.Println("  whitelist  - List current allowlist entries")
		os.Exit(1)
	}
	Command = args[0]

	conn, err := net.Dial("unix", SocketPath)
	if err != nil {
		fmt.Printf("Failed to connect to PacketYeeter at %s: %v\n", SocketPath, err)
		os.Exit(1)
	}
	defer conn.Close()

	if Command == "list" {
		_, err = conn.Write([]byte("LIST"))
		if err != nil {
			fmt.Printf("Failed to send command: %v\n", err)
			os.Exit(1)
		}

		var list ebpf.BlockedIPList
		if err := json.NewDecoder(conn).Decode(&list); err != nil {
			fmt.Printf("Failed to read response: %v\n", err)
			os.Exit(1)
		}

		if list.MonitorMode {
			fmt.Println("!!! MONITOR MODE ENABLED !!!")
			fmt.Println("These IPs have violated rules and WOULD be blocked, but traffic is currently ALLOWED.")
			fmt.Println("")
		}

		fmt.Println("Blocked IPv4:")
		for _, info := range list.IPv4 {
			fmt.Printf("  - %-15s (TTL: %s)\n", info.IP, info.RemainingTTL)
		}
		if len(list.IPv4) == 0 {
			fmt.Println("  (none)")
		}

		fmt.Println("\nBlocked IPv6:")
		for _, info := range list.IPv6 {
			fmt.Printf("  - %-39s (TTL: %s)\n", info.IP, info.RemainingTTL)
		}
		if len(list.IPv6) == 0 {
			fmt.Println("  (none)")
		}
	} else if Command == "whitelist" || Command == "allowlist" {
		_, err = conn.Write([]byte("WHITELIST"))
		if err != nil {
			fmt.Printf("Failed to send command: %v\n", err)
			os.Exit(1)
		}

		var resp allowlistResponse
		if err := json.NewDecoder(conn).Decode(&resp); err != nil {
			fmt.Printf("Failed to read response: %v\n", err)
			os.Exit(1)
		}

		if resp.Total == 0 && len(resp.Entries) == 0 {
			fmt.Println("Allowlist")
			fmt.Printf("Status: %s\n", resp.Status)
			fmt.Printf("Total: %d (static=%d dynamic=%d)\n", resp.Total, resp.Static, resp.Dynamic)
			fmt.Println("  (none)")
			return
		}

		fmt.Println("Allowlist")
		fmt.Printf("Status: %s\n", resp.Status)
		fmt.Printf("Total: %d (static=%d dynamic=%d)\n", resp.Total, resp.Static, resp.Dynamic)
		for _, entry := range resp.Entries {
			source := "static"
			if entry.Dynamic {
				source = "dynamic"
			}
			fmt.Printf("  - %-39s [%s]\n", entry.CIDR, source)
		}
	} else {
		fmt.Printf("Unknown command: %s\n", Command)
		os.Exit(1)
	}
}
