package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"lanmap/internal/db"
)

// Notifier manages webhook alerts for unauthorized devices
type Notifier struct {
	db         *db.DB
	httpClient *http.Client
	mu         sync.Mutex
	notified   map[string]string // IP -> last seen status ("up"/"down")
}

// NewNotifier creates a Notifier
func NewNotifier(database *db.DB) *Notifier {
	return &Notifier{
		db: database,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		notified: make(map[string]string),
	}
}

// ShouldAlert determines if a host should trigger an alert based on section 8.1
func (n *Notifier) ShouldAlert(h *db.Host, isNew, isReplaced bool, previousStatus string) bool {
	if h.IsApproved {
		return false
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	lastStatus, found := n.notified[h.IP]

	// 1. First time detected or IP reused by another MAC
	if isNew || isReplaced || !found {
		n.notified[h.IP] = h.Status
		return true
	}

	// 2. Transition from down -> up (re-appearance)
	if (previousStatus == "down" || lastStatus == "down") && h.Status == "up" {
		n.notified[h.IP] = "up"
		return true
	}

	// Already notified and still up -> do not flood
	n.notified[h.IP] = h.Status
	return false
}

// NotifyUnapprovedHosts sends batched alerts to all configured webhooks
func (n *Notifier) NotifyUnapprovedHosts(ctx context.Context, hosts []*db.Host) error {
	if len(hosts) == 0 {
		return nil
	}

	settings, err := n.db.GetAllSettings()
	if err != nil {
		return fmt.Errorf("failed to load webhook settings: %w", err)
	}

	gchatURL := strings.TrimSpace(settings["webhook_gchat_url"])
	slackURL := strings.TrimSpace(settings["webhook_slack_url"])
	discordURL := strings.TrimSpace(settings["webhook_discord_url"])
	teamsURL := strings.TrimSpace(settings["webhook_teams_url"])
	lineToken := strings.TrimSpace(settings["webhook_line_token"])
	lineURL := strings.TrimSpace(settings["webhook_line_url"])

	var errs []string

	// Google Chat
	if gchatURL != "" {
		if err := n.sendGoogleChat(ctx, gchatURL, hosts); err != nil {
			errs = append(errs, fmt.Sprintf("Google Chat: %v", err))
		}
	}

	// Slack
	if slackURL != "" {
		if err := n.sendSlack(ctx, slackURL, hosts); err != nil {
			errs = append(errs, fmt.Sprintf("Slack: %v", err))
		}
	}

	// Discord
	if discordURL != "" {
		if err := n.sendDiscord(ctx, discordURL, hosts); err != nil {
			errs = append(errs, fmt.Sprintf("Discord: %v", err))
		}
	}

	// Teams
	if teamsURL != "" {
		if err := n.sendTeams(ctx, teamsURL, hosts); err != nil {
			errs = append(errs, fmt.Sprintf("Teams: %v", err))
		}
	}

	// LINE Notify
	if lineToken != "" {
		if err := n.sendLINENotify(ctx, lineToken, hosts); err != nil {
			errs = append(errs, fmt.Sprintf("LINE Notify: %v", err))
		}
	} else if lineURL != "" {
		if err := n.sendSlack(ctx, lineURL, hosts); err != nil {
			errs = append(errs, fmt.Sprintf("LINE Webhook: %v", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("webhook errors: %s", strings.Join(errs, "; "))
	}

	return nil
}

// FormatSlackPayload creates Slack message payload
func FormatSlackPayload(hosts []*db.Host) map[string]interface{} {
	title := fmt.Sprintf("🚨 【lanmap 警戒】未承認端末が検出されました (%d 件)", len(hosts))
	var fields []map[string]interface{}

	for _, h := range hosts {
		mac := h.MACAddress
		if mac == "" {
			mac = "Unknown MAC"
		}
		vendor := h.VendorModel
		if vendor == "" {
			vendor = "Unknown Vendor"
		}
		name := h.Hostname
		if name == "" {
			name = "(No hostname)"
		}

		fields = append(fields, map[string]interface{}{
			"title": fmt.Sprintf("IP: %s (%s)", h.IP, name),
			"value": fmt.Sprintf("MAC: `%s` | メーカー: %s | OS: %s", mac, vendor, h.OSVendor),
			"short": false,
		})
	}

	return map[string]interface{}{
		"text": title,
		"attachments": []map[string]interface{}{
			{
				"color":  "#E01E5A",
				"title":  "未承認端末リスト (要確認)",
				"fields": fields,
				"footer": "lanmap Security Monitor",
				"ts":     time.Now().Unix(),
			},
		},
	}
}

func (n *Notifier) sendSlack(ctx context.Context, webhookURL string, hosts []*db.Host) error {
	payload := FormatSlackPayload(hosts)
	return n.postJSON(ctx, webhookURL, payload)
}

// FormatDiscordPayload creates Discord message payload
func FormatDiscordPayload(hosts []*db.Host) map[string]interface{} {
	title := fmt.Sprintf("🚨 【lanmap 警戒】未承認端末検出 (%d 件)", len(hosts))
	var fields []map[string]interface{}

	for _, h := range hosts {
		mac := h.MACAddress
		if mac == "" {
			mac = "Unknown MAC"
		}
		vendor := h.VendorModel
		if vendor == "" {
			vendor = "Unknown Vendor"
		}
		name := h.Hostname
		if name == "" {
			name = "(No hostname)"
		}

		fields = append(fields, map[string]interface{}{
			"name":   fmt.Sprintf("IP: %s [%s]", h.IP, name),
			"value":  fmt.Sprintf("MAC: `%s`\nメーカー: %s\nOS: %s", mac, vendor, h.OSVendor),
			"inline": false,
		})
	}

	return map[string]interface{}{
		"content": title,
		"embeds": []map[string]interface{}{
			{
				"title":       "未承認端末リスト (要確認)",
				"color":       15158332, // Red
				"fields":      fields,
				"footer":      map[string]string{"text": "lanmap Security Monitor"},
				"timestamp":   time.Now().UTC().Format(time.RFC3339),
			},
		},
	}
}

func (n *Notifier) sendDiscord(ctx context.Context, webhookURL string, hosts []*db.Host) error {
	payload := FormatDiscordPayload(hosts)
	return n.postJSON(ctx, webhookURL, payload)
}

// FormatTeamsPayload creates Microsoft Teams MessageCard payload
func FormatTeamsPayload(hosts []*db.Host) map[string]interface{} {
	title := fmt.Sprintf("🚨 【lanmap 警戒】未承認端末が検出されました (%d 件)", len(hosts))
	var facts []map[string]string

	for _, h := range hosts {
		mac := h.MACAddress
		if mac == "" {
			mac = "Unknown MAC"
		}
		vendor := h.VendorModel
		if vendor == "" {
			vendor = "Unknown Vendor"
		}

		facts = append(facts, map[string]string{
			"name":  h.IP,
			"value": fmt.Sprintf("ホスト名: %s | MAC: %s | メーカー: %s", h.Hostname, mac, vendor),
		})
	}

	return map[string]interface{}{
		"@type":      "MessageCard",
		"@context":   "https://schema.org/extensions",
		"themeColor": "d9534f",
		"summary":    title,
		"title":      title,
		"sections": []map[string]interface{}{
			{
				"activityTitle": "未確認端末がLANに接続されました。社内承認状態を確認してください。",
				"facts":         facts,
			},
		},
	}
}

func (n *Notifier) sendTeams(ctx context.Context, webhookURL string, hosts []*db.Host) error {
	payload := FormatTeamsPayload(hosts)
	return n.postJSON(ctx, webhookURL, payload)
}

func (n *Notifier) sendLINENotify(ctx context.Context, token string, hosts []*db.Host) error {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("\n🚨【lanmap 警戒】未承認端末検出 (%d 件)\n", len(hosts)))
	for _, h := range hosts {
		sb.WriteString(fmt.Sprintf("・IP: %s (%s)\n  MAC: %s / %s\n", h.IP, h.Hostname, h.MACAddress, h.VendorModel))
	}
	return n.postLineRawMessage(ctx, token, sb.String())
}

func (n *Notifier) postLineRawMessage(ctx context.Context, token, message string) error {
	form := url.Values{}
	form.Set("message", message)

	req, err := http.NewRequestWithContext(ctx, "POST", "https://notify-api.line.me/api/notify", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("line notify returned status %d: %s", resp.StatusCode, string(b))
	}

	return nil
}

func (n *Notifier) postJSON(ctx context.Context, endpoint string, data interface{}) error {
	body, err := json.Marshal(data)
	if err != nil {
		return err
	}

	// Retry once on transient network failure
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			time.Sleep(500 * time.Millisecond)
		}

		req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := n.httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		if resp.StatusCode >= 400 {
			respBody, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			lastErr = fmt.Errorf("webhook endpoint returned HTTP %d: %s", resp.StatusCode, string(respBody))
			continue
		}

		resp.Body.Close()
		return nil
	}

	log.Printf("[WARN] Webhook POST to %s failed: %v", endpoint, lastErr)
	return lastErr
}

// FormatGoogleChatPayload creates rich text message payload for Google Chat
func FormatGoogleChatPayload(hosts []*db.Host) map[string]interface{} {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("🚨 *【lanmap 警戒】未承認端末を検出しました (%d 件)*\n\n", len(hosts)))
	for _, h := range hosts {
		hostName := h.Hostname
		if hostName == "" {
			hostName = "ホスト名なし"
		}
		vendor := h.VendorModel
		if vendor == "" {
			vendor = "不明"
		}
		mac := h.MACAddress
		if mac == "" {
			mac = "Unknown MAC"
		}
		sb.WriteString(fmt.Sprintf("• *IP*: `%s` (%s)\n  *MAC*: `%s` / *メーカー*: %s\n  *初回検出*: %s\n\n",
			h.IP, hostName, mac, vendor, h.FirstSeen.Format("2006-01-02 15:04:05")))
	}

	return map[string]interface{}{
		"text": strings.TrimSpace(sb.String()),
	}
}

func (n *Notifier) sendGoogleChat(ctx context.Context, webhookURL string, hosts []*db.Host) error {
	payload := FormatGoogleChatPayload(hosts)
	return n.postJSON(ctx, webhookURL, payload)
}

// NotifyBroadcastStorm sends high-priority broadcast storm / excessive traffic alert
func (n *Notifier) NotifyBroadcastStorm(ctx context.Context, host *db.Host, count1m int) error {
	settings, err := n.db.GetAllSettings()
	if err != nil {
		return err
	}

	title := fmt.Sprintf("🚨 【lanmap 警戒アラート】ブロードキャスト過多を検知 (%s)", host.IP)
	body := fmt.Sprintf("端末 %s (%s / %s) から直近1分間に %d パケットのブロードキャスト通信を検知しました。\n機器の暴走、ループ配線、または不正スキャンの可能性があります。",
		host.IP, host.Hostname, host.VendorModel, count1m)

	if gchatURL := settings["webhook_gchat_url"]; gchatURL != "" {
		_ = n.postJSON(ctx, gchatURL, map[string]interface{}{
			"text": fmt.Sprintf("*%s*\n%s", title, body),
		})
	}

	if slackURL := settings["webhook_slack_url"]; slackURL != "" {
		_ = n.postJSON(ctx, slackURL, map[string]interface{}{
			"text": fmt.Sprintf("*%s*\n%s", title, body),
		})
	}

	if discordURL := settings["webhook_discord_url"]; discordURL != "" {
		_ = n.postJSON(ctx, discordURL, map[string]interface{}{
			"content": fmt.Sprintf("**%s**\n%s", title, body),
		})
	}

	if teamsURL := settings["webhook_teams_url"]; teamsURL != "" {
		_ = n.postJSON(ctx, teamsURL, map[string]interface{}{
			"@type":      "MessageCard",
			"@context":   "http://schema.org/extensions",
			"summary":    title,
			"themeColor": "DC2626",
			"title":      title,
			"text":       body,
		})
	}

	if lineToken := settings["webhook_line_token"]; lineToken != "" {
		_ = n.postLineRawMessage(ctx, lineToken, fmt.Sprintf("\n%s\n%s", title, body))
	}

	return nil
}
