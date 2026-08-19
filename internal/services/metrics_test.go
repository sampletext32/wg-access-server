package services

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/freifunkMUC/wg-access-server/internal/config"
	"github.com/freifunkMUC/wg-access-server/internal/devices"
	"github.com/freifunkMUC/wg-access-server/internal/storage"
	"github.com/freifunkMUC/wg-embed/pkg/wgembed"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// noopWireGuardInterface satisfies wgembed.WireGuardInterface without
// touching real network/kernel state.
type noopWireGuardInterface struct{}

func (noopWireGuardInterface) LoadConfig(*wgembed.ConfigFile) error { return nil }
func (noopWireGuardInterface) AddPeer(string, string, []string) error { return nil }
func (noopWireGuardInterface) ListPeers() ([]wgtypes.Peer, error) { return nil, nil }
func (noopWireGuardInterface) RemovePeer(string) error { return nil }
func (noopWireGuardInterface) PublicKey() (string, error) { return "", nil }
func (noopWireGuardInterface) Close() error { return nil }
func (noopWireGuardInterface) Ping() error { return nil }

func scrapeMetrics(t *testing.T, deps *MetricsDeps) string {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	MetricsHandler(deps).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	return rec.Body.String()
}

func TestDeviceMetrics_Disabled(t *testing.T) {
	s := storage.NewMemoryStorage()
	dm := devices.New(noopWireGuardInterface{}, s, "10.44.0.0/24", "")

	body := scrapeMetrics(t, &MetricsDeps{
		Config:        &config.AppConfig{EnableMetadata: true, EnableDeviceMetrics: false},
		DeviceManager: dm,
	})

	if strings.Contains(body, "wg_access_server_device_") {
		t.Fatalf("expected no per-device metrics when EnableDeviceMetrics is false, got:\n%s", body)
	}
}

func TestDeviceMetrics_PerDevice(t *testing.T) {
	s := storage.NewMemoryStorage()
	dm := devices.New(noopWireGuardInterface{}, s, "10.44.0.0/24", "")

	recent := time.Now()
	stale := time.Now().Add(-1 * time.Hour)

	if err := s.Save(&storage.Device{
		Owner: "user-a", Name: "laptop-1",
		ReceiveBytes: 100, TransmitBytes: 200,
		LastHandshakeTime: &recent,
	}); err != nil {
		t.Fatalf("seed device: %v", err)
	}
	if err := s.Save(&storage.Device{
		Owner: "user-b", Name: "phone-1",
		ReceiveBytes: 50, TransmitBytes: 25,
		LastHandshakeTime: &stale,
	}); err != nil {
		t.Fatalf("seed device: %v", err)
	}

	body := scrapeMetrics(t, &MetricsDeps{
		Config:        &config.AppConfig{EnableMetadata: true, EnableDeviceMetrics: true},
		DeviceManager: dm,
	})

	want := []string{
		`wg_access_server_device_connected{device="laptop-1",owner="user-a"} 1`,
		`wg_access_server_device_connected{device="phone-1",owner="user-b"} 0`,
		`wg_access_server_device_bytes_received_total{device="laptop-1",owner="user-a"} 100`,
		`wg_access_server_device_bytes_transmitted_total{device="laptop-1",owner="user-a"} 200`,
		`wg_access_server_device_last_handshake_timestamp_seconds{device="laptop-1",owner="user-a"}`,
	}
	for _, w := range want {
		if !strings.Contains(body, w) {
			t.Errorf("expected metrics output to contain %q, got:\n%s", w, body)
		}
	}
}

func TestDeviceMetrics_SameNameDifferentOwnersAreDistinct(t *testing.T) {
	// Device Name is only unique per-owner, not globally. Including owner
	// in the label set keeps such devices as separate series instead of
	// colliding.
	s := storage.NewMemoryStorage()
	dm := devices.New(noopWireGuardInterface{}, s, "10.44.0.0/24", "")

	now := time.Now()
	if err := s.Save(&storage.Device{
		Owner: "user-a", Name: "phone",
		ReceiveBytes: 100, TransmitBytes: 100,
		LastHandshakeTime: &now,
	}); err != nil {
		t.Fatalf("seed device: %v", err)
	}
	if err := s.Save(&storage.Device{
		Owner: "user-b", Name: "phone",
		ReceiveBytes: 50, TransmitBytes: 25,
		LastHandshakeTime: &now,
	}); err != nil {
		t.Fatalf("seed device: %v", err)
	}

	body := scrapeMetrics(t, &MetricsDeps{
		Config:        &config.AppConfig{EnableMetadata: true, EnableDeviceMetrics: true},
		DeviceManager: dm,
	})

	want := []string{
		`wg_access_server_device_bytes_received_total{device="phone",owner="user-a"} 100`,
		`wg_access_server_device_bytes_received_total{device="phone",owner="user-b"} 50`,
	}
	for _, w := range want {
		if !strings.Contains(body, w) {
			t.Errorf("expected metrics output to contain %q, got:\n%s", w, body)
		}
	}
}

func TestDeviceMetrics_DeletedDeviceDropsOutOfScrape(t *testing.T) {
	s := storage.NewMemoryStorage()
	dm := devices.New(noopWireGuardInterface{}, s, "10.44.0.0/24", "")

	now := time.Now()
	device := &storage.Device{
		Owner: "user-a", Name: "temp-device",
		ReceiveBytes: 10, TransmitBytes: 10,
		LastHandshakeTime: &now,
	}
	if err := s.Save(device); err != nil {
		t.Fatalf("seed device: %v", err)
	}

	deps := &MetricsDeps{
		Config:        &config.AppConfig{EnableMetadata: true, EnableDeviceMetrics: true},
		DeviceManager: dm,
	}

	before := scrapeMetrics(t, deps)
	if !strings.Contains(before, `device="temp-device"`) {
		t.Fatalf("expected device to be present before deletion, got:\n%s", before)
	}

	if err := s.Delete(device); err != nil {
		t.Fatalf("delete device: %v", err)
	}

	after := scrapeMetrics(t, deps)
	if strings.Contains(after, `device="temp-device"`) {
		t.Fatalf("expected device to be gone after deletion, got:\n%s", after)
	}
}
