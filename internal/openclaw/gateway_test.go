package openclaw

import (
	"context"
	"testing"
)

func gw(role string) (*Gateway, string) {
	g := NewGateway()
	g.RegisterPrincipal(Principal{Channel: "slack", Workspace: "acme", UserID: "u1", Role: role})
	return g, "u1"
}

func TestViewerCannotInvestigateOrCancel(t *testing.T) {
	g, uid := gw("viewer")
	cmd, reply := g.HandleCommand(context.Background(), "slack", "acme", uid, "/incident investigate checkout is slow")
	if cmd != nil {
		t.Fatal("viewer must not be able to start investigations")
	}
	if reply == nil || reply.Text == "" {
		t.Fatal("expected a denial reply")
	}
	cmd, _ = g.HandleCommand(context.Background(), "slack", "acme", uid, "/incident cancel run-123")
	if cmd != nil {
		t.Fatal("viewer must not be able to cancel runs")
	}
}

func TestViewerCanReadEvidence(t *testing.T) {
	g, uid := gw("viewer")
	cmd, reply := g.HandleCommand(context.Background(), "slack", "acme", uid, "/incident evidence run-123")
	if cmd == nil || cmd.Action != "show_evidence" {
		t.Fatalf("viewer evidence read blocked: %+v %v", cmd, reply)
	}
}

func TestOperatorCanInvestigateApproveRejectCancel(t *testing.T) {
	g, uid := gw("operator")
	for _, text := range []string{
		"/incident investigate db pool exhausted",
		"/incident approve abc",
		"/incident reject abc",
		"/incident cancel run-1",
	} {
		if cmd, _ := g.HandleCommand(context.Background(), "slack", "acme", uid, text); cmd == nil {
			t.Errorf("operator command rejected: %s", text)
		}
	}
}

func TestUnregisteredPrincipalRejected(t *testing.T) {
	g := NewGateway()
	_, reply := g.HandleCommand(context.Background(), "slack", "acme", "intruder", "/incident investigate x")
	if reply == nil || reply.Text != "You are not registered with IncidentGraph." {
		t.Fatal("unregistered principals must never reach actions")
	}
}
