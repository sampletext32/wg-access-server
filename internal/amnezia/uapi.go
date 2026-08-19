//go:build linux

package amnezia

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/crypto/curve25519"
)

const (
	DefaultInterface = "awg0"
	DefaultSocket    = "/var/run/amneziawg/awg0.sock"
)

type supervised struct {
	mu       sync.Mutex
	name     string
	socket   string
	child    *exec.Cmd
	closed   bool
	waitErr  error
	waitDone chan struct{}
}

func New(opts Options) (Interface, error) {
	if opts.InterfaceName == "" {
		opts.InterfaceName = DefaultInterface
	}
	if opts.SocketPath == "" {
		opts.SocketPath = filepath.Join(filepath.Dir(DefaultSocket), opts.InterfaceName+".sock")
	}
	if opts.ChildPath == "" {
		opts.ChildPath = "amneziawg-go"
	}

	cmd := exec.Command(opts.ChildPath, "-f", opts.InterfaceName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start amneziawg-go: %w", err)
	}

	w := &supervised{name: opts.InterfaceName, socket: opts.SocketPath, child: cmd, waitDone: make(chan struct{})}
	go func() {
		err := cmd.Wait()
		w.mu.Lock()
		w.waitErr = err
		w.mu.Unlock()
		close(w.waitDone)
	}()

	if err := waitForSocket(opts.SocketPath, 10*time.Second); err != nil {
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("wait for amneziawg UAPI: %w", err)
	}
	if err := waitForUAPI(w, 10*time.Second); err != nil {
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("wait for amneziawg UAPI readiness: %w", err)
	}
	return w, nil
}

func waitForSocket(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("socket %s did not appear", path)
}

func waitForUAPI(w *supervised, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := w.request("get=1"); err == nil {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errors.New("UAPI did not become ready")
}

func (w *supervised) request(payload string) ([]string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil, errors.New("amneziawg interface is closed")
	}
	if w.waitErr != nil {
		return nil, fmt.Errorf("amneziawg child exited: %w", w.waitErr)
	}
	conn, err := net.DialTimeout("unix", w.socket, 3*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte(payload + "\n\n")); err != nil {
		return nil, err
	}
	var lines []string
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	for _, line := range lines {
		if line == "errno=0" {
			return lines, nil
		}
		if strings.HasPrefix(line, "errno=") && line != "errno=0" {
			return nil, fmt.Errorf("UAPI error: %s", line)
		}
	}
	return lines, nil
}

func (w *supervised) Configure(c DeviceConfig) error {
	var b strings.Builder
	put := func(k, v string) {
		if v != "" {
			fmt.Fprintf(&b, "%s=%s\n", k, v)
		}
	}
	key, err := ParseKey(c.PrivateKey)
	if err != nil {
		return fmt.Errorf("private key: %w", err)
	}
	put("private_key", hex.EncodeToString(key[:]))
	if c.ListenPort > 0 {
		put("listen_port", strconv.Itoa(c.ListenPort))
	}
	for k, v := range map[string]*uint32{"jc": c.AWG.JC, "jmin": c.AWG.JMin, "jmax": c.AWG.JMax, "s1": c.AWG.S1, "s2": c.AWG.S2, "s3": c.AWG.S3, "s4": c.AWG.S4} {
		if v != nil {
			put(k, strconv.FormatUint(uint64(*v), 10))
		}
	}
	for k, v := range map[string]*string{"h1": c.AWG.H1, "h2": c.AWG.H2, "h3": c.AWG.H3, "h4": c.AWG.H4, "i1": c.AWG.I1, "i2": c.AWG.I2, "i3": c.AWG.I3, "i4": c.AWG.I4, "i5": c.AWG.I5, "content_padding_addition": c.AWG.ContentPaddingAddition, "rekey_after_time": c.AWG.RekeyAfterTime, "rekey_timeout": c.AWG.RekeyTimeout, "reject_after_time": c.AWG.RejectAfterTime, "keepalive_timeout": c.AWG.KeepaliveTimeout, "max_handshake_attempts": c.AWG.MaxHandshakeAttempts} {
		if v != nil {
			put(k, *v)
		}
	}
	if c.AWG.HeaderProtectionKey != "" {
		key, err := ParseKey(c.AWG.HeaderProtectionKey)
		if err != nil {
			return err
		}
		put("header_protection_key", hex.EncodeToString(key[:]))
	}
	if _, err := w.request("set=1\n" + b.String()); err != nil {
		return fmt.Errorf("configure device: %w", err)
	}
	link, err := netlink.LinkByName(w.name)
	if err != nil {
		return err
	}
	for _, address := range c.Address {
		a, err := netlink.ParseAddr(address)
		if err != nil {
			return err
		}
		if err := netlink.AddrAdd(link, a); err != nil && !errors.Is(err, syscall.EEXIST) {
			return err
		}
	}
	if c.MTU > 0 {
		if err := netlink.LinkSetMTU(link, c.MTU); err != nil {
			return err
		}
	}
	return netlink.LinkSetUp(link)
}

func (w *supervised) AddPeer(publicKey, presharedKey string, addresses []string) error {
	key, err := ParseKey(publicKey)
	if err != nil {
		return err
	}
	b := &strings.Builder{}
	fmt.Fprintf(b, "public_key=%s\nreplace_allowed_ips=true\n", hex.EncodeToString(key[:]))
	if presharedKey != "" {
		p, err := ParseKey(presharedKey)
		if err != nil {
			return err
		}
		fmt.Fprintf(b, "preshared_key=%s\n", hex.EncodeToString(p[:]))
	}
	for _, address := range addresses {
		if _, _, err := net.ParseCIDR(address); err != nil {
			return err
		}
		fmt.Fprintf(b, "allowed_ip=%s\n", address)
	}
	_, err = w.request("set=1\n" + b.String())
	return err
}

func (w *supervised) RemovePeer(publicKey string) error {
	key, err := ParseKey(publicKey)
	if err != nil {
		return err
	}
	_, err = w.request("set=1\n" + fmt.Sprintf("public_key=%s\nremove=true", hex.EncodeToString(key[:])))
	return err
}

func (w *supervised) ListPeers() ([]Peer, error) {
	lines, err := w.request("get=1")
	if err != nil {
		return nil, err
	}
	var peers []Peer
	var peer *Peer
	flush := func() {
		if peer != nil {
			peers = append(peers, *peer)
			peer = nil
		}
	}
	for _, line := range lines {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if key == "public_key" {
			flush()
			if value == "" {
				continue
			}
			peer = &Peer{PublicKey: hexKey(value)}
			continue
		}
		if peer == nil {
			continue
		}
		switch key {
		case "endpoint":
			peer.Endpoint, _ = net.ResolveUDPAddr("udp", value)
		case "allowed_ip":
			if _, p, e := net.ParseCIDR(value); e == nil {
				peer.AllowedIPs = append(peer.AllowedIPs, netipPrefix(p))
			}
		case "last_handshake_time_sec":
			peer.LastHandshakeTime = time.Unix(parseInt(value), int64(peer.LastHandshakeTime.Nanosecond()))
		case "last_handshake_time_nsec":
			peer.LastHandshakeTime = time.Unix(peer.LastHandshakeTime.Unix(), parseInt(value))
		case "rx_bytes":
			peer.ReceiveBytes = parseInt(value)
		case "tx_bytes":
			peer.TransmitBytes = parseInt(value)
		}
	}
	flush()
	return peers, nil
}

func (w *supervised) PublicKey() (string, error) {
	lines, err := w.request("get=1")
	if err != nil {
		return "", err
	}
	for _, line := range lines {
		if strings.HasPrefix(line, "private_key=") {
			privateBytes, err := hex.DecodeString(strings.TrimPrefix(line, "private_key="))
			if err != nil || len(privateBytes) != 32 {
				return "", errors.New("invalid device private key")
			}
			var privateKey, publicKey [32]byte
			copy(privateKey[:], privateBytes)
			curve25519.ScalarBaseMult(&publicKey, &privateKey)
			return Key(publicKey).String(), nil
		}
	}
	return "", errors.New("device public key is not configured")
}

func (w *supervised) Ping() error { _, err := w.request("get=1"); return err }

func (w *supervised) Close() error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return nil
	}
	w.closed = true
	child := w.child
	w.mu.Unlock()
	if child.Process != nil {
		_ = child.Process.Signal(syscall.SIGTERM)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	select {
	case <-w.waitDone:
	case <-ctx.Done():
		_ = child.Process.Kill()
	}
	logrus.Debugf("amneziawg interface %s stopped", w.name)
	return nil
}

func parseInt(v string) int64 { n, _ := strconv.ParseInt(v, 10, 64); return n }
func hexKey(v string) string {
	b, err := hex.DecodeString(v)
	if err != nil {
		return ""
	}
	if len(b) != 32 {
		return ""
	}
	var k Key
	copy(k[:], b)
	return k.String()
}
func netipPrefix(p *net.IPNet) netip.Prefix {
	prefix, _ := netip.ParsePrefix(p.String())
	return prefix
}
