package monitoring

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rcourtman/pulse-go-rewrite/internal/models"
	"github.com/rcourtman/pulse-go-rewrite/pkg/proxmox"
)

func observedPermissionPollError(t *testing.T, status int) error {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		fmt.Fprint(w, "permission denied: API error 403")
	}))
	defer server.Close()
	client, err := proxmox.NewClient(proxmox.ClientConfig{Host: server.URL, TokenName: "test@pve!monitor", TokenValue: "test"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.GetNodePendingUpdates(context.Background(), "node")
	if err == nil {
		t.Fatal("expected HTTP error")
	}
	return fmt.Errorf("wrapped: %w", err)
}

type countedPendingUpdatesClient struct {
	*pendingUpdatesPVEClient
	calls int
}

func (c *countedPendingUpdatesClient) GetNodePendingUpdates(ctx context.Context, node string) ([]proxmox.AptPackage, error) {
	c.calls++
	return c.pendingUpdatesPVEClient.GetNodePendingUpdates(ctx, node)
}

func TestPendingUpdatesPermissionBackoffPreservesEvidenceAndRecovers(t *testing.T) {
	for _, retained := range []bool{false, true} {
		t.Run(fmt.Sprintf("retained=%v", retained), func(t *testing.T) {
			m := &Monitor{nodePendingUpdatesCache: make(map[string]pendingUpdatesCache)}
			checkedAt := time.Now().Add(-pendingUpdatesCacheTTL - time.Minute)
			wantStatus := "unavailable"
			if retained {
				m.nodePendingUpdatesCache["lab-node"] = pendingUpdatesCache{count: 7, checkedAt: checkedAt}
				wantStatus = "stale"
			}
			client := &countedPendingUpdatesClient{pendingUpdatesPVEClient: &pendingUpdatesPVEClient{stubPVEClient: &stubPVEClient{}, err: observedPermissionPollError(t, http.StatusForbidden)}}
			for i := 0; i < 3; i++ {
				node := &models.Node{}
				m.applyNodePendingUpdates(context.Background(), "lab", client, proxmox.Node{Node: "node"}, "lab-node", "online", node)
				if node.PendingUpdatesStatus != wantStatus || node.PendingUpdatesReason != "permission_denied" {
					t.Fatalf("denied evidence = %+v", node)
				}
				if retained && (node.PendingUpdates != 7 || !node.PendingUpdatesCheckedAt.Equal(checkedAt)) {
					t.Fatalf("lost retained evidence: %+v", node)
				}
				if !retained && !node.PendingUpdatesCheckedAt.IsZero() {
					t.Fatal("denial created successful evidence")
				}
			}
			if client.calls != 1 {
				t.Fatalf("denied requests = %d, want 1", client.calls)
			}
			cached := m.nodePendingUpdatesCache["lab-node"]
			cached.permissionRetryAt = time.Now().Add(-time.Second)
			m.nodePendingUpdatesCache["lab-node"] = cached
			client.err = nil
			node := &models.Node{}
			m.applyNodePendingUpdates(context.Background(), "lab", client, proxmox.Node{Node: "node"}, "lab-node", "online", node)
			if client.calls != 2 || node.PendingUpdatesStatus != "checked" || node.PendingUpdates != 0 || node.PendingUpdatesCheckedAt.IsZero() || node.PendingUpdatesReason != "" {
				t.Fatalf("recovered evidence = %+v, requests %d", node, client.calls)
			}
		})
	}
}

func TestPendingUpdatesBackoffRequiresObservedForbidden(t *testing.T) {
	m := &Monitor{}
	client := &countedPendingUpdatesClient{pendingUpdatesPVEClient: &pendingUpdatesPVEClient{stubPVEClient: &stubPVEClient{}, err: observedPermissionPollError(t, http.StatusBadGateway)}}
	for i := 0; i < 2; i++ {
		m.applyNodePendingUpdates(context.Background(), "lab", client, proxmox.Node{Node: "node"}, "lab-node", "online", &models.Node{})
	}
	if client.calls != 2 {
		t.Fatalf("non-403 requests = %d, want 2", client.calls)
	}
}

func TestGuestMemoryPermissionBackoffIgnoresKnownLinuxFastRetry(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusBadGateway} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			m := &Monitor{guestMetadataCache: map[string]guestMetadataCacheEntry{guestMetadataCacheKey("lab", "node", 105): {osName: "Linux"}}}
			client := &guestMemoryAgentTestClient{stubPVEClient: &stubPVEClient{}, memErr: observedPermissionPollError(t, status)}
			if _, err := m.getVMAgentMemoryAvailability(context.Background(), client, "lab", "node", 105); err == nil {
				t.Fatal("expected unavailable memory")
			}
			key := guestMemoryCacheKey("lab", "node", 105)
			entry := m.vmAgentMemCache[key]
			entry.fetchedAt = time.Now().Add(-time.Minute)
			m.vmAgentMemCache[key] = entry
			if _, err := m.getVMAgentMemoryAvailability(context.Background(), client, "lab", "node", 105); err == nil {
				t.Fatal("negative cache became successful memory")
			}
			wantCalls := 1
			if status != http.StatusForbidden {
				wantCalls = 2
			}
			if client.memCalls != wantCalls {
				t.Fatalf("memory requests = %d, want %d", client.memCalls, wantCalls)
			}
			entry = m.vmAgentMemCache[key]
			entry.fetchedAt = time.Now().Add(-vmAgentMemNegativeTTL - time.Second)
			m.vmAgentMemCache[key] = entry
			client.memErr = nil
			client.memAvailable = 1024
			got, err := m.getVMAgentMemoryAvailability(context.Background(), client, "lab", "node", 105)
			if err != nil || got.EffectiveAvailable != 1024 || client.memCalls != wantCalls+1 {
				t.Fatalf("recovery = %+v, %v, calls %d", got, err, client.memCalls)
			}
		})
	}
}
