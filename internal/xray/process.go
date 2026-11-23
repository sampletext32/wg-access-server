package xray

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/freifunkMUC/wg-access-server/internal/config"
)

// startupTimeout bounds how long a freshly started process gets to answer on
// its management port before the supervisor treats the start as failed. Xray
// is ready in milliseconds; anything slower is a broken configuration.
const startupTimeout = 10 * time.Second

// stopTimeout is how long the process gets to exit after an interrupt before it
// is killed.
const stopTimeout = 5 * time.Second

// Server is the Xray process and everything that makes it look like a
// dataplane: its configuration file, the users it should have, and the
// supervisor that restarts it.
//
// The process is a child of this one rather than a sidecar container. That
// keeps the deployment to one container and one process tree, and it means the
// configuration file is written by the same process that owns the devices, so
// it cannot be stale by more than one reconcile.
type Server struct {
	cfg        config.VLESSConfig
	dir        string
	configPath string
	users      *users
	wait       *backoff

	mu      sync.Mutex
	cmd     *exec.Cmd
	running bool
	closed  bool
	ctx     context.Context
}

// New prepares the process without starting it. The directory it works in holds
// the configuration file, which carries the REALITY private key, so it is
// created with the process's own permissions and removed on Close.
func New(cfg config.VLESSConfig) (*Server, error) {
	dir, err := os.MkdirTemp("", "wg-access-server-xray-")
	if err != nil {
		return nil, fmt.Errorf("failed to create the directory for the Xray configuration: %w", err)
	}
	return &Server{
		cfg:        cfg,
		dir:        dir,
		configPath: filepath.Join(dir, "server.json"),
		users:      newUsers(),
		wait:       newBackoff(),
	}, nil
}

// Start writes the configuration, starts the process and waits until it answers.
// The supervisor takes over from there and restarts it if it exits.
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	s.ctx = ctx
	s.mu.Unlock()

	if err := writeConfig(s.configPath, s.cfg, s.users.list()); err != nil {
		return err
	}
	if err := s.startProcess(ctx); err != nil {
		return err
	}
	if err := s.waitReady(); err != nil {
		_ = s.stopProcess()
		return err
	}
	logrus.Infof("VLESS is listening on :%d, pretending to be https://%s (clients connect to %s:%d)",
		s.cfg.ListenPort, s.cfg.CoverHost, s.cfg.PublicHost, s.cfg.PublicPort)
	go s.supervise()
	return nil
}

// Upsert makes sure the process knows the user. A user added while the process
// is down is simply in the configuration the next start reads.
func (s *Server) Upsert(id string) error {
	if err := validateUserID(id); err != nil {
		return err
	}
	if s.users.add(id) {
		return nil
	}
	if !s.runningNow() {
		return nil
	}
	if err := s.addUser(id); err != nil {
		// Keep the memory and the process in agreement: the user is not
		// there, so it must not be in the rendered configuration either.
		s.users.remove(id)
		return err
	}
	return nil
}

// Remove deletes the user from the process, or only from the configuration if
// the process is down.
func (s *Server) Remove(id string) error {
	if !s.users.remove(id) {
		return nil
	}
	if !s.runningNow() {
		return nil
	}
	return s.removeUser(id)
}

// runningNow reports whether the process is up. It is the question the user
// methods ask before deciding between the API and the configuration file.
func (s *Server) runningNow() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

// startProcess launches the binary and starts reading its log.
func (s *Server) startProcess(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, s.cfg.Binary, "run", "-c", s.configPath)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to read the Xray log: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to read the Xray log: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start %q: %w", s.cfg.Binary, err)
	}
	go logLines(stdout)
	go logLines(stderr)

	s.mu.Lock()
	s.cmd = cmd
	s.running = true
	s.mu.Unlock()
	return nil
}

// waitReady waits until the management API answers, which is the only proof
// that the process not only started but read its configuration.
func (s *Server) waitReady() error {
	deadline := time.Now().Add(startupTimeout)
	for {
		if err := s.Ping(); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the Xray process did not answer on its management port within %s", startupTimeout)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// supervise restarts the process when it exits, with a growing delay so that a
// configuration it rejects does not turn into a busy loop. The users are
// rendered again on every start, so a restart does not lose them.
func (s *Server) supervise() {
	for {
		s.mu.Lock()
		cmd := s.cmd
		s.mu.Unlock()
		if cmd == nil {
			return
		}

		err := cmd.Wait()
		s.mu.Lock()
		s.running = false
		closed := s.closed
		s.mu.Unlock()
		if closed {
			return
		}
		delay := s.wait.next()
		if err != nil {
			logrus.Errorf("the Xray process exited: %v; restarting in %s", err, delay)
		} else {
			logrus.Errorf("the Xray process exited unexpectedly; restarting in %s", delay)
		}

		select {
		case <-time.After(delay):
		case <-s.ctx.Done():
			return
		}

		if err := writeConfig(s.configPath, s.cfg, s.users.list()); err != nil {
			logrus.Errorf("failed to rewrite the Xray configuration: %v", err)
			continue
		}
		if err := s.startProcess(s.ctx); err != nil {
			logrus.Errorf("failed to restart the Xray process: %v", err)
			continue
		}
		if err := s.waitReady(); err != nil {
			logrus.Errorf("the restarted Xray process did not become ready: %v", err)
			_ = s.stopProcess()
			continue
		}
		s.wait.reset()
		logrus.Info("the Xray process is running again")
	}
}

// stopProcess asks the process to exit and kills it if it does not. Xray writes
// nothing that has to be flushed, so a kill is not a loss - but an interrupt
// lets it close its listeners in order.
func (s *Server) stopProcess() error {
	s.mu.Lock()
	cmd := s.cmd
	s.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		_ = cmd.Process.Kill()
		return nil
	}
	deadline := time.Now().Add(stopTimeout)
	for time.Now().Before(deadline) {
		if !s.runningNow() {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = cmd.Process.Kill()
	return nil
}

// Close stops the process and removes its directory.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()

	if err := s.stopProcess(); err != nil {
		return err
	}
	if err := os.RemoveAll(s.dir); err != nil {
		return fmt.Errorf("failed to remove the Xray directory: %w", err)
	}
	return nil
}

// logLines copies the process's own log into ours, one line at a time. Xray
// logs warnings about the configuration at startup that are worth keeping, and
// a crash is explained there rather than by the exit code.
func logLines(reader io.Reader) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		logrus.Debugf("xray: %s", line)
	}
}
