// Package openclaw implements the OPTIONAL messaging ingress (Slack/Telegram).
// OpenClaw is a gateway, never the runtime: it maps channel messages to
// IncidentGraph API calls and posts status back. Investigation state always
// lives in Postgres.
package openclaw

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/incidentgraph/incidentgraph/internal/observability"
)

// Principal maps an external identity to an IncidentGraph role. Approval
// rights are explicit; not every chat user can approve privileged operations.
type Principal struct {
	Channel   string // slack|telegram
	Workspace string
	UserID    string
	Role      string // viewer|operator|admin
}

// Gateway processes inbound commands and records outbound replies.
type Gateway struct {
	mu         sync.Mutex
	principals map[string]Principal // key: channel:workspace:userID
	replies    []Reply
	log        *observability.Logger
}

func NewGateway() *Gateway {
	return &Gateway{principals: map[string]Principal{}, log: observability.New("openclaw")}
}

func (g *Gateway) RegisterPrincipal(p Principal) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.principals[p.Channel+":"+p.Workspace+":"+p.UserID] = p
}

func (g *Gateway) Identify(channel, workspace, userID string) (Principal, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	p, ok := g.principals[channel+":"+workspace+":"+userID]
	return p, ok
}

// Reply is a message the gateway would post back to the channel.
type Reply struct {
	Channel string `json:"channel"`
	Text    string `json:"text"`
}

// HandleCommand parses "/incident ..." style messages and returns the API
// action the caller should perform. The gateway itself never holds state.
type Command struct {
	Action    string // investigate|show_evidence|approve|reject|cancel
	Argument  string
	Principal Principal
}

func (g *Gateway) HandleCommand(ctx context.Context, channel, workspace, userID, text string) (*Command, *Reply) {
	p, ok := g.Identify(channel, workspace, userID)
	if !ok {
		return nil, &Reply{Channel: channel, Text: "You are not registered with IncidentGraph."}
	}
	fields := strings.Fields(strings.TrimSpace(text))
	if len(fields) == 0 || !strings.HasPrefix(fields[0], "/incident") {
		return nil, nil
	}
	if len(fields) < 2 {
		return g.reply(channel, "Usage: /incident <investigate|evidence|approve|reject|cancel> [args]")
	}
	cmd := &Command{Principal: p}
	switch strings.ToLower(fields[1]) {
	case "investigate":
		if len(fields) < 3 {
			return g.reply(channel, "Usage: /incident investigate <description>")
		}
		cmd.Action = "investigate"
		cmd.Argument = strings.Join(fields[2:], " ")
	case "evidence":
		cmd.Action = "show_evidence"
		if len(fields) >= 3 {
			cmd.Argument = fields[2]
		}
	case "approve", "reject":
		if p.Role != "operator" && p.Role != "admin" {
			return g.reply(channel, "Only operators/admins may approve or reject actions.")
		}
		if len(fields) < 3 {
			return g.reply(channel, fmt.Sprintf("Usage: /incident %s <approval_id>", fields[1]))
		}
		cmd.Action = strings.ToLower(fields[1])
		cmd.Argument = fields[2]
	case "cancel":
		cmd.Action = "cancel"
		if len(fields) >= 3 {
			cmd.Argument = fields[2]
		}
	default:
		return g.reply(channel, "Unknown subcommand.")
	}
	return cmd, nil
}

func (g *Gateway) reply(channel, text string) (*Command, *Reply) {
	g.mu.Lock()
	g.replies = append(g.replies, Reply{Channel: channel, Text: text})
	g.mu.Unlock()
	return nil, &Reply{Channel: channel, Text: text}
}

// PostStatus sends run lifecycle updates back through the channel adapter.
func PostStatus(ctx context.Context, webhookURL string, payload map[string]any) error {
	if webhookURL == "" {
		return nil
	}
	b, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, strings.NewReader(string(b)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("openclaw webhook unreachable: %w", err)
	}
	defer resp.Body.Close()
	return nil
}
