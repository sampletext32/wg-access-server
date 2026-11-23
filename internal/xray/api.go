package xray

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// apiTimeout bounds one management call. Adding a user is a local gRPC call to
// a process on loopback: a second is a lot, and anything longer means the
// process is gone rather than busy.
const apiTimeout = 5 * time.Second

// callAPI runs one management command and returns its combined output. The
// command is the Xray binary itself, which is the reason this package shells
// out instead of speaking gRPC: the binary is already there, and its CLI is a
// stable interface where the protobuf definitions are not.
//
// The server flag goes between the subcommand and the operands. After the
// operands the CLI takes it for the name of the file to read - `xray api adu
// <file> --server=...` tries to open a file called "--server=...", which is
// what the first deployment of this code did.
func (s *Server) callAPI(ctx context.Context, args ...string) (string, error) {
	callCtx, cancel := context.WithTimeout(ctx, apiTimeout)
	defer cancel()

	command := []string{"api", args[0], fmt.Sprintf("--server=127.0.0.1:%d", s.cfg.APIPort)}
	command = append(command, args[1:]...)

	cmd := exec.CommandContext(callCtx, s.cfg.Binary, command...)
	output, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(output))
	if err != nil {
		return text, fmt.Errorf("xray %s failed: %w: %s", args[0], err, text)
	}
	return text, nil
}

// addUser tells the running process about one user. The CLI reads the fragment
// from a file, so one is written next to the configuration and removed again;
// it holds a user id, which is not a secret, but leaving copies around is
// pointless.
func (s *Server) addUser(id string) error {
	fragment, err := userFragment(s.cfg, id)
	if err != nil {
		return err
	}
	path := filepath.Join(s.dir, "user-"+id+".json")
	if err := os.WriteFile(path, fragment, 0o600); err != nil {
		return fmt.Errorf("failed to write the user fragment for %s: %w", id, err)
	}
	defer func() { _ = os.Remove(path) }()

	output, err := s.callAPI(s.context(), "adu", path)
	if err != nil {
		return err
	}
	logrus.Debugf("VLESS user %s added: %s", id, oneLine(output))
	return nil
}

// removeUser deletes one user. Xray reports a user that is not there as an
// error, which is not one for us: the desired state is reached either way. The
// check is on the CLI's own message, so it is written as narrowly as the known
// wording allows and the version is pinned in the Dockerfile - a change there
// shows up as a failed removal, never as a silently ignored one.
func (s *Server) removeUser(id string) error {
	output, err := s.callAPI(s.context(), "rmu", "-tag="+vlessTag, id)
	if err != nil {
		lower := strings.ToLower(output)
		if strings.Contains(lower, "not found") || strings.Contains(lower, "not exist") || strings.Contains(lower, "no such") {
			return nil
		}
		return err
	}
	logrus.Debugf("VLESS user %s removed: %s", id, oneLine(output))
	return nil
}

// statsQuery is the answer of `xray api statsquery`, which is a list rather
// than a map.
type statsQuery struct {
	Stat []struct {
		Name  string `json:"name"`
		Value int64  `json:"value"`
	} `json:"stat"`
}

// Stats reads the per-user counters. The names are
// `user>>> <id> >>>traffic>>>uplink|downlink`, with the id being the email the
// user was created with - which this server sets to the user id itself.
func (s *Server) Stats() (map[string]Traffic, error) {
	if !s.runningNow() {
		return map[string]Traffic{}, nil
	}
	output, err := s.callAPI(s.context(), "statsquery", "-pattern", "user>>>")
	if err != nil {
		return nil, err
	}
	// An empty answer is "{}" rather than a document with an empty list.
	if output == "{}" || output == "" {
		return map[string]Traffic{}, nil
	}
	var query statsQuery
	if err := json.Unmarshal([]byte(output), &query); err != nil {
		return nil, fmt.Errorf("failed to read the VLESS counters: %w", err)
	}
	counters := make(map[string]Traffic, len(query.Stat))
	for _, stat := range query.Stat {
		id, direction, ok := parseStatName(stat.Name)
		if !ok {
			continue
		}
		traffic := counters[id]
		switch direction {
		case "uplink":
			traffic.Uplink = stat.Value
		case "downlink":
			traffic.Downlink = stat.Value
		}
		counters[id] = traffic
	}
	return counters, nil
}

// parseStatName splits `user>>> <id> >>>traffic>>> <direction>`.
func parseStatName(name string) (id string, direction string, ok bool) {
	parts := strings.Split(name, ">>>")
	if len(parts) != 4 || parts[0] != "user" || parts[2] != "traffic" {
		return "", "", false
	}
	return parts[1], parts[3], true
}

// Ping asks the process whether it is there. The counters are the cheapest
// question that needs the API to answer, so a failure here means the process is
// down rather than that a user is missing.
func (s *Server) Ping() error {
	_, err := s.callAPI(s.context(), "statsquery", "-pattern", "user>>>")
	return err
}

func oneLine(output string) string {
	return strings.Join(strings.Fields(output), " ")
}
