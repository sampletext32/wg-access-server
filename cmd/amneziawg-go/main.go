//go:build linux

package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/ipc"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"golang.org/x/sys/unix"
)

func main() {
	if len(os.Args) != 3 || os.Args[1] != "-f" {
		fmt.Fprintf(os.Stderr, "usage: %s -f INTERFACE\n", os.Args[0])
		os.Exit(1)
	}
	name := os.Args[2]
	tunDevice, err := tun.CreateTUN(name, device.DefaultMTU)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create TUN: %v\n", err)
		os.Exit(1)
	}
	uapiFile, err := ipc.UAPIOpen(name)
	if err != nil {
		_ = tunDevice.Close()
		fmt.Fprintf(os.Stderr, "open UAPI: %v\n", err)
		os.Exit(1)
	}
	uapi, err := ipc.UAPIListen(name, uapiFile)
	if err != nil {
		_ = tunDevice.Close()
		fmt.Fprintf(os.Stderr, "listen UAPI: %v\n", err)
		os.Exit(1)
	}
	defer uapi.Close()

	dev := device.NewDevice(tunDevice, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "("+name+") "))
	defer dev.Close()

	errs := make(chan error, 1)
	go func() {
		for {
			connection, err := uapi.Accept()
			if err != nil {
				errs <- err
				return
			}
			go dev.IpcHandle(connection)
		}
	}()

	term := make(chan os.Signal, 1)
	signal.Notify(term, syscall.SIGTERM, os.Interrupt)
	defer signal.Stop(term)
	select {
	case <-term:
	case <-errs:
	case <-dev.Wait():
	}
	_ = unix.Unlink(fmt.Sprintf("/var/run/amneziawg/%s.sock", name))
}
