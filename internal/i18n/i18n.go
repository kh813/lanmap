package i18n

import (
	"fmt"
	"net/http"
	"strings"
)

const (
	LangEN = "en"
	LangJA = "ja"

	CookieName = "lanmap_lang"
)

// SupportedLanguages lists all supported language codes
var SupportedLanguages = []string{LangEN, LangJA}

// DetectLanguage detects the preferred language from request
// Priority: 1. Cookie ("lanmap_lang") -> 2. Query param ("lang") -> 3. Accept-Language header -> 4. Default ("en")
func DetectLanguage(r *http.Request) string {
	if r == nil {
		return LangEN
	}

	// 1. Check Cookie
	if cookie, err := r.Cookie(CookieName); err == nil && cookie.Value != "" {
		val := strings.ToLower(strings.TrimSpace(cookie.Value))
		if val == LangJA {
			return LangJA
		}
		if val == LangEN {
			return LangEN
		}
	}

	// 2. Check Query parameter
	if q := r.URL.Query().Get("lang"); q != "" {
		val := strings.ToLower(strings.TrimSpace(q))
		if val == LangJA {
			return LangJA
		}
		if val == LangEN {
			return LangEN
		}
	}

	// 3. Check Accept-Language header
	accept := r.Header.Get("Accept-Language")
	if accept != "" {
		// Example: "ja,en-US;q=0.9,en;q=0.8"
		for _, part := range strings.Split(accept, ",") {
			locale := strings.TrimSpace(strings.Split(part, ";")[0])
			locale = strings.ToLower(locale)
			if strings.HasPrefix(locale, "ja") {
				return LangJA
			}
			if strings.HasPrefix(locale, "en") {
				return LangEN
			}
		}
	}

	// 4. Default is English
	return LangEN
}

// T translates a key into the specified language
func T(lang string, key string) string {
	lang = strings.ToLower(strings.TrimSpace(lang))
	if lang != LangJA && lang != LangEN {
		lang = LangEN
	}

	// Search in target language
	if dict, ok := translations[lang]; ok {
		if msg, ok := dict[key]; ok {
			return msg
		}
	}

	// Fallback to English
	if lang != LangEN {
		if dict, ok := translations[LangEN]; ok {
			if msg, ok := dict[key]; ok {
				return msg
			}
		}
	}

	// Fallback to key itself
	return key
}

// TF translates a key with fmt.Sprintf formatting arguments
func TF(lang string, key string, args ...interface{}) string {
	raw := T(lang, key)
	if len(args) > 0 {
		return fmt.Sprintf(raw, args...)
	}
	return raw
}

// Translation dictionary
var translations = map[string]map[string]string{
	LangEN: {
		// General
		"app_title":          "lanmap - LAN Host Manager & Security Detector",
		"loading":            "Loading...",
		"add":                "Add",
		"edit":               "Edit",
		"delete":             "Delete",
		"cancel":             "Cancel",
		"save":               "Save",
		"close":              "Close",
		"search":             "Search",
		"search_placeholder": "Search (IP, hostname, model, port)...",
		"unknown":            "Unknown",
		"enabled":            "Enabled",
		"disabled":           "Paused",
		"online":             "Online",
		"offline":            "Offline",
		"test":               "Test",
		"success":            "Success",
		"error":              "Error",
		"none":               "None",

		// Sidebar
		"sidebar_segments":         "Segments",
		"sidebar_all_hosts":        "All Hosts",
		"sidebar_uncategorized":    "Uncategorized",
		"sidebar_theme_toggle":     "Toggle Theme (Light/Dark)",
		"sidebar_settings_tooltip": "Open System Settings & Updates",
		"sidebar_unadded_badge":    "%d unregistered local network interface(s) detected",
		"sidebar_btn_add_segment":  "+ Add",

		// Main Table Header & Actions
		"table_total_hosts":      "Total %d host(s) registered (Auto-refreshes every 30s / Hover IP for details)",
		"table_filter_online":    "🟢 Online Only",
		"table_filter_all":       "📋 All",
		"table_btn_add":          "Add Host",
		"table_btn_scan_now":     "Scan Now",
		"table_guide_banner":     "Click any row to open detailed modal with <strong>7-day Ping response charts and uptime analytics</strong>.",
		"table_guide_banner_sub": "Click: Detailed Modal / Hover: Quick Popover",
		"table_no_hosts":         "No hosts found. Click \"Scan Now\" or manually add a host.",
		"table_no_match":         "🔍 No matching hosts found for the current search.",

		// Table Columns
		"col_ip_details":   "IP Address / Details",
		"col_hostname":     "Hostname",
		"col_display_name": "Display Name",
		"col_vendor_model": "Vendor / Model",
		"col_os":           "Estimated OS",
		"col_connection":   "Connection",
		"col_approval":     "Approval",
		"col_status":       "Status",
		"col_latency":      "Latency",
		"col_static_ip":    "Static IP",
		"col_actions":      "Actions",

		// Approval & Status Badges
		"badge_approved":     "🟢 Approved",
		"badge_dhcp_new":     "🟢 DHCP 🆕",
		"badge_dhcp_dynamic": "🟢 DHCP Dynamic",
		"badge_new":          "🆕 NEW",
		"badge_unapproved":   "🔴 Unapproved",
		"badge_up":           "🟢 up",
		"badge_down":         "⚪ Down",
		"badge_conn_wired":   "🔌 Wired",
		"badge_conn_wifi":    "📶 Wi-Fi",
		"badge_storm_alert":  "🚨 High Broadcast / Storm Detected",
		"badge_storm_title":  "Recent 1-min broadcasts: %d packets (Storm anomaly)",
		"badge_storm_text":   "💥 Traffic Storm (%d pkts/min)",
		"badge_rtt_fast":     "Latency: Good (Wired / Strong Wi-Fi)",
		"badge_rtt_normal":   "Latency: Normal (Wi-Fi)",
		"badge_rtt_slow":     "Latency: High / Congested",

		// Popover
		"popover_uptime":       "Uptime",
		"popover_conn_type":    "🔗 Connection:",
		"popover_web_service":  "🌐 Web / Port 80/443:",
		"popover_open_browser": "Open in Browser ↗",
		"popover_open_ports":   "🚪 Open Ports (Detected):",
		"popover_ping_chart":   "Ping Response Trend (Past 24h)",
		"popover_first_seen":   "First Seen:",
		"popover_last_seen":    "Last Seen:",
		"popover_no_ports":     "No open service ports detected",
		"popover_no_hostname":  "No hostname",

		// Action Menu
		"action_mark_approved":      "✅ Mark as Approved",
		"action_mark_unapproved":    "🔴 Mark as Unapproved",
		"action_protect":            "📌 Protect from Deletion",
		"action_unprotect":          "📌 Remove Deletion Protection",
		"action_toggle_dhcp_mark":   "🟢 Mark as DHCP Dynamic",
		"action_toggle_dhcp_unmark": "🔌 Set as Static IP",
		"action_edit_host":          "✏️ Edit Host Info & Name",
		"action_delete_host":        "🗑️ Delete Host",

		// Segment Menu
		"seg_menu_edit":    "✏️ Edit Segment Info",
		"seg_menu_disable": "⏸️ Pause Scanning This Segment",
		"seg_menu_enable":  "▶️ Enable Scanning This Segment",
		"seg_menu_delete":  "🗑️ Delete Segment",

		// Add Host Modal
		"add_host_title":       "Manually Add Host",
		"add_host_ip_label":    "IPv4 Address *",
		"add_host_name_label":  "Display Name / Notes",
		"add_host_name_ph":     "e.g. Core Switch 1F, Test Server",
		"add_host_seg_label":   "Segment",
		"add_host_approve_chk": "Mark as Approved immediately upon adding",
		"add_host_protect_chk": "Protect from auto-deletion (Prevent retention purge)",
		"add_host_submit":      "Add Host",

		// Edit Host Modal
		"edit_host_title":        "✏️ Edit Host Information",
		"edit_host_disp_label":   "Display Name",
		"edit_host_disp_ph":      "Custom display name",
		"edit_host_vendor_label": "Vendor / Model Name",
		"edit_host_vendor_ph":    "e.g. Apple MacBook Pro, Buffalo WSR-3200",
		"edit_host_os_label":     "Estimated OS",
		"edit_host_os_ph":        "e.g. macOS Sonoma, Ubuntu 24.04, Windows 11",
		"edit_host_conn_label":   "Connection Medium",
		"edit_host_conn_auto":    "Auto Detect",
		"edit_host_conn_wired":   "🔌 Wired LAN",
		"edit_host_conn_wifi":    "📶 Wi-Fi",
		"edit_host_static_chk":   "Static IP Device (Managed)",
		"edit_host_submit":       "Save Changes",

		// Segment Modal
		"seg_modal_title_add":          "Add Network Segment",
		"seg_modal_title_edit":         "✏️ Edit Segment",
		"seg_modal_unadded_header":      "💡 Detected Unregistered / Deleted Local NICs (%d)",
		"seg_modal_unadded_sub":         "Re-register with one click",
		"seg_modal_main_lan":            "Main LAN",
		"seg_modal_local_lan":           "Local LAN",
		"seg_modal_unadded_btn":         "One-Click Add",
		"seg_modal_unadded_edit":        "📝 Edit",
		"seg_modal_or_manual":           "or enter manually",
		"seg_modal_name_label":          "Segment Display Name *",
		"seg_modal_name_ph":             "e.g. Office LAN, Guest Wi-Fi",
		"seg_modal_cidr_label":          "CIDR Subnet *",
		"seg_modal_cidr_ph":             "e.g. 192.168.1.0/24, 10.8.0.0/24",
		"seg_modal_cidr_help":           "Specify the target IPv4 subnet in CIDR notation to scan.",
		"seg_modal_dhcp_label":          "DHCP Dynamic IP Range (Optional, multiple supported)",
		"seg_modal_dhcp_sub":            "Multiple ranges separated by commas",
		"seg_modal_dhcp_ph":             "e.g. 100-150, 180-200 or 192.168.1.100-192.168.1.200",
		"seg_modal_dhcp_help":           "Specifying the dynamic DHCP range suppresses alerts for unapproved dynamic hosts and displays them with a green badge (🟢). Multiple ranges can be separated by commas.",
		"seg_modal_dhcp_manual":         "🔒 Lock manual IP range (Stop auto-estimation/adjustment when marking hosts)",
		"seg_modal_presets":             "Presets:",
		"seg_modal_dhcp_suggest":        "💡 Estimated: %s",
		"seg_modal_dhcp_suggest_title":  "Auto-estimated from distribution of detected Wi-Fi/client devices",
		"seg_modal_dhcp_multi_title":    "Example of multiple ranges",
		"seg_modal_dhcp_clear":          "Clear",
		"seg_modal_iface_label":         "Binding Interface / NIC (Optional)",
		"seg_modal_iface_ph":            "e.g. eth0, en0 (Default if empty)",
		"seg_modal_enabled_chk":         "Enable scanning for this segment",
		"seg_modal_submit":              "Save",

		// Settings Modal
		"settings_title":             "lanmap System Settings",
		"settings_theme_label":       "🎨 Theme (Light / Dark)",
		"settings_theme_light":       "☀️ Light Theme (Default)",
		"settings_theme_dark":        "🌙 Dark Theme",
		"settings_scan_mode_label":   "🛡️ Network Scan Mode (Stealth / Safe Mode)",
		"settings_scan_mode_help":    "Controls whether active TCP port probes are sent to devices during periodic background scans.",
		"settings_scan_mode_safe":    "🛡️ Safe Mode (Recommended - Low Noise & Zero IDS Alerts)",
		"settings_scan_mode_safe_desc":"Only uses ICMP Ping, ARP, and mDNS/DNS. Zero port scanning. Prevents false positive alerts from security software (ESET, Windows Defender, UTM).",
		"settings_scan_mode_full":    "🔍 Full Audit Mode (Probes 17 Common Ports)",
		"settings_scan_mode_full_desc":"Actively checks common ports (SSH, HTTP, SMB, etc.) on alive hosts. Use only in your own lab or authorized networks.",
		"settings_retention_label":   "🧹 Offline Host Auto-Cleanup Retention Policy",
		"settings_retention_help":    "Automatically delete unapproved and unprotected hosts that have not been seen for the specified period.",
		"settings_days_30":           "30 Days",
		"settings_days_60":           "60 Days",
		"settings_days_90":           "90 Days (Default)",
		"settings_days_180":          "180 Days",
		"settings_days_365":          "365 Days (1 Year)",
		"settings_days_0":            "Do not auto-delete (Disabled)",
		"settings_webhook_label":     "🚨 Webhook Notification Settings for Unapproved Devices (Instant Alert)",
		"settings_webhook_test_hint": "* Test connectivity with the 'Send Test' button",
		"settings_webhook_test_btn":  "🔔 Send Test",
		"settings_gchat_hint":        "* Enter the Webhook URL obtained from Google Chat Space settings -> Apps & Integrations -> Webhooks.",
		"settings_tls_label":         "🔒 Custom TLS / HTTPS Certificate (Optional)",
		"settings_tls_help":          "If not specified, automatically generated self-signed certificate (certs/cert.pem) will be used.",
		"settings_tls_cert_label":    "Certificate file path (cert.pem):",
		"settings_tls_key_label":     "Private key file path (key.pem):",
		"settings_update_label":      "🚀 System Update (Self-Update)",
		"settings_update_help":       "Queries GitHub Releases for the latest binary and updates in-place safely with one click.",
		"settings_update_check_btn":  "Check for Updates",
		"settings_update_checking":   "⏳ Checking GitHub Releases...",
		"settings_whitelist_btn":     "Device Whitelist Ledger",
		"settings_btn_save":          "💾 Save Settings",

		// Host Detail Modal
		"detail_title":                  "📊 Host Detail Analytics",
		"detail_static_badge":           "Static IP",
		"detail_unnamed":                "Unnamed",
		"detail_7d_title":               "Past 7-Day Ping Response Trends & Liveness Monitoring",
		"detail_ping_test_btn":          "⚡ Run Ping Now",
		"detail_ping_sending":           "⏳ Sending Ping probe...",
		"detail_uptime_7d":              "Uptime (7 Days)",
		"detail_avg_rtt":                "Avg Latency (RTT)",
		"detail_min_max_rtt":            "Min / Max Latency",
		"detail_jitter_label":           "Jitter (Latency Variance)",
		"detail_ping_trend_title":       "Ping Response Time Trend (ms)",
		"detail_ping_trend_legend":      "Blue: RTT Trend / Dashed: Unmeasured",
		"detail_uptime_blocks_title":    "7-Day Uptime Blocks (4h Slots)",
		"detail_uptime_block_up":        "UP",
		"detail_uptime_block_loss":      "Partial Loss",
		"detail_uptime_block_down":      "Down",
		"detail_uptime_block_unmeasured":"Unmeasured",
		"detail_7d_ago":                 "7 days ago",
		"detail_3d_ago":                 "3 days ago",
		"detail_now":                    "Now",
		"detail_profile_title":          "Network & Device Profile",
		"detail_mac_oui":                "MAC Address / Vendor (OUI):",
		"detail_unknown_vendor":         "Unknown",
		"detail_conn_type":              "Connection Medium:",
		"detail_conn_reason":            "Reason:",
		"detail_os_model":               "Estimated OS / Model:",
		"detail_not_detected":           "Not detected",
		"detail_mdns_model":             "mDNS Model:",
		"detail_open_ports":             "Detected Open Ports:",
		"detail_probe_ports_btn":        "🔍 Probe Open Ports",
		"detail_probing_ports":          "⏳ Probing open ports & services...",
		"detail_probe_ports_success":    "Port scan completed: %s",
		"detail_probe_ports_none":       "No open ports found (Host is stealth)",
		"detail_stealth":                "No primary ports responding (Stealth)",
		"detail_web_admin":              "🌐 Web Admin:",
		"detail_upnp_info":              "📻 UPnP Device Info:",
		"detail_tls_cert":               "🔒 TLS Certificate:",
		"detail_first_seen":             "First Seen:",
		"detail_last_seen":              "Last Seen:",
		"detail_last_port_scan":         "Last Port Audit:",
		"detail_next_port_scan":         "Next Patrol (Jittered):",
		"detail_risk_warning":           "Security Alerts / Listening Services:",
		"risk_vpn_detected":             "🚨 VPN Server Detected",
		"risk_remote_access":            "⚠️ Remote Access Listening",
		"risk_remote_login":             "⚠️ Remote Login Listening",
		"detail_traffic":                "Broadcast Traffic:",
		"detail_traffic_unit":           "pkt/min",
		"detail_traffic_storm":          "(Storm Anomaly)",
		"detail_edit_host_btn":          "✏️ Edit Host Details",

		// Whitelist Modal
		"whitelist_title":            "Device Whitelist Ledger (Batch Management)",
		"whitelist_sub":              "Devices with registered hostnames or MAC addresses are automatically marked as \"🟢 Approved\" during scans and excluded from alerts.",
		"whitelist_import_title":     "📥 Batch Import via CSV / Text",
		"whitelist_format_hint":      "Format: Hostname, MAC Address, Serial Number, Device/Owner Name, Note",
		"whitelist_note":             "* Supports TSV (Excel copy-paste) and CSV. Header row presence is auto-detected.",
		"whitelist_import_btn":       "Import & Match Immediately",
		"whitelist_registered_title": "Registered Whitelist Entries (%d)",
		"whitelist_clear_all":        "Clear All",
		"whitelist_confirm_clear":    "Clear all whitelist entries?",
		"whitelist_col_hostname":     "Hostname",
		"whitelist_col_mac":          "MAC Address",
		"whitelist_col_serial":       "Serial Number",
		"whitelist_col_owner":        "Device Name / Owner",
		"whitelist_col_note":         "Note",
		"whitelist_col_action":       "Action",
		"whitelist_empty":            "No whitelist entries registered yet. Import using the form above.",

		// Language Switcher
		"lang_en": "EN",
		"lang_ja": "JP",
	},

	LangJA: {
		// General
		"app_title":          "lanmap - LAN Host Manager & Security Detector",
		"loading":            "読み込み中...",
		"add":                "追加",
		"edit":               "編集",
		"delete":             "削除",
		"cancel":             "キャンセル",
		"save":               "保存",
		"close":              "閉じる",
		"search":             "検索",
		"search_placeholder": "検索 (IP, ホスト名, モデル, ポート等)...",
		"unknown":            "不明",
		"enabled":            "有効",
		"disabled":           "停止中",
		"online":             "オンライン",
		"offline":            "オフライン",
		"test":               "テスト",
		"success":            "成功",
		"error":              "エラー",
		"none":               "なし",

		// Sidebar
		"sidebar_segments":         "セグメント一覧",
		"sidebar_all_hosts":        "すべてのホスト",
		"sidebar_uncategorized":    "未分類",
		"sidebar_theme_toggle":     "テーマ切替 (ライト/ダーク)",
		"sidebar_settings_tooltip": "システム設定・アップデートを開く",
		"sidebar_unadded_badge":    "未登録のローカルNICが %d 件あります",
		"sidebar_btn_add_segment":  "+ 追加",

		// Main Table Header & Actions
		"table_total_hosts":      "合計 %d 台の端末が登録されています (30秒ごとに自動更新 / IPホバーでWeb名・型番・SSL・ポート詳細表示)",
		"table_filter_online":    "🟢 オンラインのみ",
		"table_filter_all":       "📋 すべて",
		"table_btn_add":          "ホスト追加",
		"table_btn_scan_now":     "Scan Now",
		"table_guide_banner":     "任意の行をクリックすると、<strong>過去7日間のPingレスポンスグラフ・死活分析</strong>を含む詳細モーダルが開きます。",
		"table_guide_banner_sub": "クリック: 詳細モーダル / ホバー: クイック概要",
		"table_no_hosts":         "ホストが見つかりません。「Scan Now」を実行するか、手動でホストを追加してください。",
		"table_no_match":         "🔍 検索条件に一致する端末が見つかりませんでした。",

		// Table Columns
		"col_ip_details":   "IPアドレス / 詳細",
		"col_hostname":     "ホスト名",
		"col_display_name": "表示名",
		"col_vendor_model": "メーカー / モデル",
		"col_os":           "推定OS",
		"col_connection":   "接続形態",
		"col_approval":     "承認",
		"col_status":       "状態",
		"col_latency":      "応答速度",
		"col_static_ip":    "固定IP",
		"col_actions":      "操作",

		// Approval & Status Badges
		"badge_approved":     "🟢 承認済",
		"badge_dhcp_new":     "🟢 DHCP 🆕",
		"badge_dhcp_dynamic": "🟢 DHCP動的",
		"badge_new":          "🆕 NEW",
		"badge_unapproved":   "🔴 未承認",
		"badge_up":           "🟢 up",
		"badge_down":         "⚪ Down",
		"badge_conn_wired":   "🔌 有線LAN",
		"badge_conn_wifi":    "📶 Wi-Fi",
		"badge_storm_alert":  "🚨 ブロードキャスト過多・ストーム異常検知",
		"badge_storm_title":  "直近1分間のブロードキャスト送信数: %d パケット (異常過多)",
		"badge_storm_text":   "💥 異常通信 (%d pkt/分)",
		"badge_rtt_fast":     "応答速度: 良好 (有線 / 強電波)",
		"badge_rtt_normal":   "応答速度: 通常 (Wi-Fi)",
		"badge_rtt_slow":     "応答速度: やや遅延 / 混雑",

		// Popover
		"popover_uptime":       "稼働率",
		"popover_conn_type":    "🔗 接続形態:",
		"popover_web_service":  "🌐 Webサービス (Port 80/443):",
		"popover_open_browser": "ブラウザで開く ↗",
		"popover_open_ports":   "🚪 開放ポート (自動検出):",
		"popover_ping_chart":   "Ping レスポンス推移 (過去24時間)",
		"popover_first_seen":   "初回検出:",
		"popover_last_seen":    "最終確認:",
		"popover_no_ports":     "検出された開放サービスポートなし",
		"popover_no_hostname":  "ホスト名なし",

		// Action Menu
		"action_mark_approved":      "✅ 承認済みに変更",
		"action_mark_unapproved":    "🔴 未承認に戻す",
		"action_protect":            "📌 自動削除から保護",
		"action_unprotect":          "📌 保護を解除",
		"action_toggle_dhcp_mark":   "🟢 DHCP動的端末としてマーク",
		"action_toggle_dhcp_unmark": "🔌 固定IP / 静的端末に変更",
		"action_edit_host":          "✏️ ホスト情報・表示名を編集",
		"action_delete_host":        "🗑️ このホストを削除",

		// Segment Menu
		"seg_menu_edit":    "✏️ セグメント情報を編集",
		"seg_menu_disable": "⏸️ このセグメントのスキャンを停止",
		"seg_menu_enable":  "▶️ このセグメントのスキャンを有効化",
		"seg_menu_delete":  "🗑️ このセグメントを削除",

		// Add Host Modal
		"add_host_title":       "ホストを手動追加",
		"add_host_ip_label":    "IPv4 アドレス *",
		"add_host_name_label":  "表示名・メモ",
		"add_host_name_ph":     "例: 1F基幹スイッチ, 検証用サーバー",
		"add_host_seg_label":   "所属セグメント",
		"add_host_approve_chk": "登録と同時に承認済みにする",
		"add_host_protect_chk": "自動削除から保護する (保管日数を超過しても保持)",
		"add_host_submit":      "ホストを追加",

		// Edit Host Modal
		"edit_host_title":        "✏️ ホスト情報の編集",
		"edit_host_disp_label":   "表示名 (別名)",
		"edit_host_disp_ph":      "任意の分かりやすい名前",
		"edit_host_vendor_label": "メーカー / モデル名",
		"edit_host_vendor_ph":    "例: Apple MacBook Pro, Buffalo WSR-3200",
		"edit_host_os_label":     "推定OS",
		"edit_host_os_ph":        "例: macOS Sonoma, Ubuntu 24.04, Windows 11",
		"edit_host_conn_label":   "接続形態",
		"edit_host_conn_auto":    "自動判定",
		"edit_host_conn_wired":   "🔌 有線LAN",
		"edit_host_conn_wifi":    "📶 Wi-Fi",
		"edit_host_static_chk":   "固定IP機器として管理",
		"edit_host_submit":       "変更を保存",

		// Segment Modal
		"seg_modal_title_add":          "ネットワークセグメントの追加",
		"seg_modal_title_edit":         "✏️ セグメントの編集",
		"seg_modal_unadded_header":      "💡 検出された未登録 / 削除済みのローカルNIC (%d件)",
		"seg_modal_unadded_sub":         "ワンクリックで再登録可能",
		"seg_modal_main_lan":            "メインLAN",
		"seg_modal_local_lan":           "ローカルLAN",
		"seg_modal_unadded_btn":         "ワンクリック追加",
		"seg_modal_unadded_edit":        "📝 編集",
		"seg_modal_or_manual":           "または手動で入力",
		"seg_modal_name_label":          "セグメント表示名 *",
		"seg_modal_name_ph":             "例: 本社LAN, 開発拠点VPN",
		"seg_modal_cidr_label":          "CIDR サブネット表記 *",
		"seg_modal_cidr_ph":             "例: 192.168.1.0/24, 10.8.0.0/24",
		"seg_modal_cidr_help":           "スキャン対象のIPv4サブネット（CIDR表記）を指定します。",
		"seg_modal_dhcp_label":          "DHCP IPレンジ (任意・複数指定可)",
		"seg_modal_dhcp_sub":            "カンマ区切りで複数指定可能",
		"seg_modal_dhcp_ph":             "例: 100-150, 180-200 または 192.168.1.100-192.168.1.200",
		"seg_modal_dhcp_help":           "動的に払い出されるDHCP端末帯域を指定すると、未承認時の赤色警戒表示を抑え、スマートな緑色バッジ (🟢) で表示します。複数レンジはカンマ区切りで指定できます。",
		"seg_modal_dhcp_manual":         "🔒 手入力したIPレンジを固定する (端末マーク時の自動推測・自動調整を停止)",
		"seg_modal_presets":             "プリセット:",
		"seg_modal_dhcp_suggest":        "💡 推定: %s",
		"seg_modal_dhcp_suggest_title":  "検出されたWi-Fi/クライアント端末の分布から自動推定",
		"seg_modal_dhcp_multi_title":    "複数範囲の例",
		"seg_modal_dhcp_clear":          "クリア",
		"seg_modal_iface_label":         "バインドNIC / インターフェース (任意)",
		"seg_modal_iface_ph":            "例: eth0, en0 (未指定でデフォルト)",
		"seg_modal_enabled_chk":         "スキャンを有効にする",
		"seg_modal_submit":              "保存",

		// Settings Modal
		"settings_title":             "lanmap システム設定",
		"settings_theme_label":       "🎨 テーマ表示切替 (Theme)",
		"settings_theme_light":       "☀️ ライトテーマ (既定)",
		"settings_theme_dark":        "🌙 ダークテーマ",
		"settings_scan_mode_label":   "🛡️ ネットワークスキャン動作モード (セーフモード設定)",
		"settings_scan_mode_help":    "定期バックグラウンドスキャン時に、各端末への能動的なTCPポート接続を行うかを制御します。",
		"settings_scan_mode_safe":    "🛡️ セーフモード (推奨・低ノイズ & セキュリティ警告ゼロ)",
		"settings_scan_mode_safe_desc":"Ping、ARPテーブル、リバースDNS/mDNSのみで静かに監視します。ポートスキャンを行わないため、ESET等のセキュリティソフトやUTMから攻撃と誤認識されません。",
		"settings_scan_mode_full":    "🔍 フルスキャンモード (主要17ポート詳細調査)",
		"settings_scan_mode_full_desc":"生存端末に対して主要ポート（SSH, HTTP, SMB等）の開放状況を定期調査します。社内検証環境や許可された自社LANでのみご利用ください。",
		"settings_retention_label":   "🧹 古いホストの自動クリーンアップ保持期間 (Retention Policy)",
		"settings_retention_help":    "最終検出日時から指定期間経過した未保護・未承認端末を自動削除します。",
		"settings_days_30":           "30 日間",
		"settings_days_60":           "60 日間",
		"settings_days_90":           "90 日間 (既定)",
		"settings_days_180":          "180 日間",
		"settings_days_365":          "365 日間 (1年)",
		"settings_days_0":            "自動削除しない (無効)",
		"settings_webhook_label":     "🚨 未承認端末検出時の Webhook 通知設定 (即時アラート)",
		"settings_webhook_test_hint": "※各項目の「テスト送信」で疎通確認が可能",
		"settings_webhook_test_btn":  "🔔 テスト送信",
		"settings_gchat_hint":        "※ Google Chat スペース設定 ➔「アプリと統合」➔「Webhookを追加」で取得したURLを入力してください（ChatroomのブラウザURLではありません）。",
		"settings_tls_label":         "🔒 カスタム TLS / HTTPS 証明書設定 (任意)",
		"settings_tls_help":          "未指定時は自動生成された自己署名証明書（certs/cert.pem）を使用します。",
		"settings_tls_cert_label":    "証明書ファイルパス (cert.pem):",
		"settings_tls_key_label":     "秘密鍵ファイルパス (key.pem):",
		"settings_update_label":      "🚀 システムアップデート (Self-Update)",
		"settings_update_help":       "GitHub Releases から最新バイナリを照会し、ワンクリックで安全にインプレース更新・自動再起動します。",
		"settings_update_check_btn":  "最新アップデートを確認",
		"settings_update_checking":   "⏳ GitHub Releases を照会中...",
		"settings_whitelist_btn":     "社内端末台帳 (ホワイトリスト)",
		"settings_btn_save":          "💾 設定を保存",

		// Host Detail Modal
		"detail_title":                  "📊 ホスト詳細分析",
		"detail_static_badge":           "固定IP",
		"detail_unnamed":                "名称未設定",
		"detail_7d_title":               "過去7日間の Ping レスポンス推移 & 死活モニタリング",
		"detail_ping_test_btn":          "⚡ 今すぐ Ping 診断",
		"detail_ping_sending":           "⏳ Ping プローブを送信中...",
		"detail_uptime_7d":              "稼働率 (7日間)",
		"detail_avg_rtt":                "平均応答時間 (RTT)",
		"detail_min_max_rtt":            "最小 / 最大遅延",
		"detail_jitter_label":           "ジッター (遅延の揺らぎ)",
		"detail_ping_trend_title":       "Ping 応答時間推移 (ms)",
		"detail_ping_trend_legend":      "青線: RTT推移 / 破線: 未計測区間",
		"detail_uptime_blocks_title":    "7日間 稼働ブロック (4時間毎のスロット)",
		"detail_uptime_block_up":        "UP",
		"detail_uptime_block_loss":      "一部ロス",
		"detail_uptime_block_down":      "Down",
		"detail_uptime_block_unmeasured":"未計測",
		"detail_7d_ago":                 "7日前",
		"detail_3d_ago":                 "3日前",
		"detail_now":                    "現在",
		"detail_profile_title":          "ネットワーク & デバイスプロファイル",
		"detail_mac_oui":                "MACアドレス / ベンダー (OUI):",
		"detail_unknown_vendor":         "不明 (Unknown)",
		"detail_conn_type":              "接続形態:",
		"detail_conn_reason":            "判定根拠:",
		"detail_os_model":               "推定OS / モデル:",
		"detail_not_detected":           "未検出",
		"detail_mdns_model":             "mDNSモデル:",
		"detail_open_ports":             "検出されたオープンポート:",
		"detail_probe_ports_btn":        "🔍 開放ポートを診断",
		"detail_probing_ports":          "⏳ 開放ポート・サービスを診断中...",
		"detail_probe_ports_success":    "ポート診断完了: %s",
		"detail_probe_ports_none":       "開放ポートなし (全ポート応答なし / ステルス)",
		"detail_stealth":                "主要ポートの応答なし (ステルス)",
		"detail_web_admin":              "🌐 Web管理画面:",
		"detail_upnp_info":              "📻 UPnP機器情報:",
		"detail_tls_cert":               "🔒 TLS証明書:",
		"detail_first_seen":             "初回検出 (First Seen):",
		"detail_last_seen":              "最終確認 (Last Seen):",
		"detail_last_port_scan":         "最終ポート監査:",
		"detail_next_port_scan":         "次回巡回 (揺らぎ適用):",
		"detail_risk_warning":           "セキュリティ警戒 / 待受サービス:",
		"risk_vpn_detected":             "🚨 VPNサーバー検知",
		"risk_remote_access":            "⚠️ リモートアクセス待受",
		"risk_remote_login":             "⚠️ リモートログイン待受",
		"detail_traffic":                "通信トラフィック:",
		"detail_traffic_unit":           "pkt/分",
		"detail_traffic_storm":          "(異常過多)",
		"detail_edit_host_btn":          "✏️ ホスト情報を編集",

		// Whitelist Modal
		"whitelist_title":            "社内端末台帳 (ホワイトリスト一括管理)",
		"whitelist_sub":              "登録されたホスト名・MACアドレスの端末はスキャン時に自動で「🟢 承認済み」となり、アラート通知から除外されます。",
		"whitelist_import_title":     "📥 CSV / テキスト貼り付け一括インポート",
		"whitelist_format_hint":      "形式: ホスト名, MACアドレス, シリアル番号, 端末名/所有者, 備考",
		"whitelist_note":             "※ TSV（Excelコピー）またはカンマ区切りCSVに対応。ヘッダー行の有無は自動判定されます。",
		"whitelist_import_btn":       "インポート & 即時照合承認",
		"whitelist_registered_title": "登録済みホワイトリスト一覧 (%d 件)",
		"whitelist_clear_all":        "全件クリア",
		"whitelist_confirm_clear":    "ホワイトリスト台帳を全件クリアしますか？",
		"whitelist_col_hostname":     "ホスト名",
		"whitelist_col_mac":          "MACアドレス",
		"whitelist_col_serial":       "シリアル番号",
		"whitelist_col_owner":        "端末名 / 所有者",
		"whitelist_col_note":         "備考",
		"whitelist_col_action":       "操作",
		"whitelist_empty":            "台帳データはまだ登録されていません。上のフォームからインポートしてください。",

		// Language Switcher
		"lang_en": "EN",
		"lang_ja": "JP",
	},
}
