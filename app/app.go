package app

import (
	"context"
	"errors"
	"fmt"
	"github.com/bepass-org/psiphon/psiphon"
	"github.com/bepass-org/psiphon/warp"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"
)

func RunPsiphon(bindAddress string, proxyAddr string, country string, workingDirectory string, config string, ctx context.Context) error {
	// run psiphon
	err := psiphon.RunPsiphon(proxyAddr, bindAddress, country, workingDirectory, config, ctx)
	if err != nil {
		log.Printf("unable to run psiphon %v\n", err)
		return fmt.Errorf("unable to run psiphon %v\n", err)
	}
	log.Println("Running psiphon was successful.")
	return nil
}

func findFreePort(network string) (string, error) {
	if network == "udp" {
		addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
		if err != nil {
			return "", err
		}

		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			return "", err
		}
		defer conn.Close()

		return conn.LocalAddr().(*net.UDPAddr).String(), nil
	}
	// Listen on TCP port 0, which tells the OS to pick a free port.
	listener, err := net.Listen(network, "127.0.0.1:0")
	if err != nil {
		return "", err // Return error if unable to listen on a port
	}
	defer listener.Close() // Ensure the listener is closed when the function returns

	// Get the port from the listener's address
	addr := listener.Addr().String()

	return addr, nil
}

func createPrimaryAndSecondaryIdentities(license string) error {
	// make primary identity
	_license := license
	if _license == "notset" {
		_license = ""
	}
	warp.UpdatePath("./primary")
	if !warp.CheckProfileExists(license) {
		err := warp.LoadOrCreateIdentity(_license)
		if err != nil {
			log.Printf("error: %v", err)
			return fmt.Errorf("error: %v", err)
		}
	}
	// make secondary
	warp.UpdatePath("./secondary")
	if !warp.CheckProfileExists(license) {
		err := warp.LoadOrCreateIdentity(_license)
		if err != nil {
			log.Printf("error: %v", err)
			return fmt.Errorf("error: %v", err)
		}
	}
	return nil
}

func makeDirs() error {
	stuffDir := "stuff"
	primaryDir := "primary"
	secondaryDir := "secondary"

	// Check if 'stuff' directory exists, if not create it
	if _, err := os.Stat(stuffDir); os.IsNotExist(err) {
		log.Println("'stuff' directory does not exist, creating it...")
		if err := os.Mkdir(stuffDir, 0755); err != nil {
			log.Println("Error creating 'stuff' directory:", err)
			return errors.New("Error creating 'stuff' directory:" + err.Error())
		}
	}

	// Create 'primary' and 'secondary' directories if they don't exist
	for _, dir := range []string{primaryDir, secondaryDir} {
		if _, err := os.Stat(filepath.Join(stuffDir, dir)); os.IsNotExist(err) {
			log.Printf("Creating '%s' directory...\n", dir)
			if err := os.Mkdir(filepath.Join(stuffDir, dir), 0755); err != nil {
				log.Printf("Error creating '%s' directory: %v\n", dir, err)
				return fmt.Errorf("Error creating '%s' directory: %v\n", dir, err)
			}
		}
	}
	log.Println("'primary' and 'secondary' directories are ready")
	return nil
}
func isPortOpen(address string, timeout time.Duration) bool {
	// Try to establish a connection
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	return true
}

func waitForPortToGetsOpenOrTimeout(addressToCheck string) {
	timeout := 5 * time.Second
	checkInterval := 500 * time.Millisecond

	// Set a deadline for when to stop checking
	deadline := time.Now().Add(timeout)

	for {
		if time.Now().After(deadline) {
			log.Fatalf("Timeout reached, port %s is not open", addressToCheck)
		}

		if isPortOpen(addressToCheck, checkInterval) {
			log.Printf("Port %s is now open", addressToCheck)
			break
		}

		time.Sleep(checkInterval)
	}
}
