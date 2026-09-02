# lanmap (lmap) - LAN Host Manager & Security Detector System Design Document

## 1. システム概要と目的
`lanmap`（CLIエイリアス: `lmap`）は、LANおよび拠点間VPN/リモートアクセスVPN等に接続されたネットワーク機器・ホストを自動検出し、**社内LAN内への不正端末・未確認端末（持ち込みPC、野良ルーター、シャドーIT等）の接続を早期発見・警戒してネットワークセキュリティを守る**ための単一バイナリ型Webアプリケーションです。

スプレッドシート感覚で全ホストを一括管理（IP、ホスト名、メーカー/モデル、承認状態など）できるほか、新規端末の**即時アラート通知（Webhook）**や **Uptime Kuma** との Socket.IO 双方向連携をサポートし、直感的な三点リーダー (`...`) メニューから安全な監視・承認管理を行います。

---

## 2. アーキテクチャ & 技術スタック

### 2.1 主要技術
* **実行形態**: シングルバイナリ（CGO非依存、外部依存なし）
* **バックエンド**: Go 1.22+ (`go:embed` によるフロントエンド資材の内包)
* **フロントエンド**: HTML5 / CSS (Tailwind CSS等) / HTMX (ビルド環境不要、SSR)
* **データベース**: SQLite (`modernc.org/sqlite` による純粋Go実装)
* **通信プロトコル**: ICMP Ping, mDNS, NBNS, UPnP/SSDP, Webhook (Slack/Discord等), Socket.IO (Uptime Kuma)

### 2.2 主要依存ライブラリ (`go.mod`)
* `modernc.org/sqlite` : CGO不要の純粋Go製SQLiteドライバー
* `golang.org/x/net/icmp` : ICMP Pingパッケージ（LANスキャン用、非特権ソケット運用。2.5節参照）
* `github.com/breml/go-uptime-kuma-client` : Uptime Kuma Socket.IO通信用（Uptime Kuma専用に作られた非公式クライアント。汎用の `graarh/golang-socketio` はSocket.IO v4系との互換性issueが未解決のため不採用）
* `golang.org/x/sys` : Windows サービス管理 (`golang.org/x/sys/windows/svc`) 用

### 2.3 【絶対遵守】設計ガイドライン（安全性・プライバシーの原則）

1. **ネットワーク負荷の絶対抑止**
   * **レートリミット（並列数制限）**: 同時パケット送信数を制御し、古いルーターやWi-Fi機器の処理負荷を圧迫しない。
   * **スキャン頻度の最適化**: デフォルト間隔（5〜15分）での定期実行とし、不要な常時パケット送信を排除。
   * **広域帯域（VPN）配慮**: 複数セグメントスキャン時は同時に行わず順次実行し、拠点間帯域を保護する。
   * **軽量プロトコル限定**: ICMP Ping, mDNS, NBNS, UPnP/SSDP, OUIローカル照合等、機器の通常応答範囲のパケットのみ使用。

2. **プライバシーとセキュリティの尊重**
   * **非侵入的（Non-intrusive）スキャンの徹底**: 認証情報の奪取、個人ログインユーザーの特定、認証を要するローカルデータの取得は一切行わない。
   * **攻撃的手法の排除**: ポートスキャンや攻撃的パケット（SYN Flood等）は使用せず、機器の誤作動やセキュリティアラートを発生させない安全な検出のみを行う。

### 2.4 メーカー/モデル推定用 OUIデータベース
MACアドレス上位3バイト（OUI）からメーカーを推定するため、IEEE公開のMA-L（MAC Address Block Large）割当リストを元にした静的データを `internal/scanner/data/oui.csv`（または `.txt`）としてリポジトリに同梱し、`go:embed` でバイナリに内包する。外部ネットワークへの都度問い合わせは行わない（オフライン環境・プライバシー配慮のため）。定期的な手動更新（例: 半年〜1年毎にIEEE公開データを再取得し同梱データを更新）を運用ルールとする。

### 2.5 実行権限の最小化方針（Non-root運用）

`lanmap` はできる限り一般ユーザー権限で実行できることを設計方針とし、root/Administrator権限を必須としない。

* **Linux / macOS**: ICMP Pingは生ソケット（`ip4:icmp`）ではなく、非特権のデータグラムICMPソケット（`golang.org/x/net/icmp` の `"udp4"`/`"udp6"` ネットワーク種別）を優先的に使用する。
  * macOSは非特権ICMPデータグラムソケットを標準でサポートしており、追加設定不要。
  * Linuxはカーネルの `net.ipv4.ping_group_range` sysctl設定に依存する（多くのディストリビューションはデフォルトで一般ユーザーに許可済み）。許可されていない環境で非特権ICMPの送信に失敗した場合は、生ソケットへのフォールバックは行わず、エラーログと共に「`sudo sysctl -w net.ipv4.ping_group_range="0 2147483647"` 等の設定変更、または `setcap cap_net_raw+ep` の付与が必要」という具体的な対処ガイダンスを表示する。
* **Windows**: 生ICMPソケットではなく、管理者権限を必要としないWin32 API `IcmpSendEcho`（`syscall`経由）を使用する。
* **サービス化時の実行ユーザー**: `systemd`/`launchd`/Windowsサービスいずれも、可能な限り専用の非特権ユーザー（またはログインユーザー）で実行する構成をデフォルトとし、root/Administrator専用ユーザーでの常駐は必須としない。

### 2.6 データディレクトリ構成

実行ファイルと同じディレクトリを既定のデータディレクトリとし、以下のファイル・ディレクトリを配置する（環境変数 `LANMAP_DATA_DIR` で変更可能）。

```text
<lanmap実行ファイルのディレクトリ>/
├── lanmap.db          # SQLiteデータベースファイル
└── certs/             # TLS証明書格納ディレクトリ (10.1節)
    ├── cert.pem        # 自己署名証明書（自動生成、または利用者が配置するカスタム証明書）
    └── key.pem         # 秘密鍵
```

データディレクトリが存在しない場合は初回起動時に自動作成する。

---

## 3. ディレクトリ・ファイル構成

```text
lanmap/
├── cmd/
│   └── lanmap/
│       └── main.go           # エントリーポイント (CLI引数解析、バージョン定義、サーバー起動)
├── internal/
│   ├── config/               # 設定管理 (ポート決定、環境変数、スキャン間隔/並列数)
│   │   └── config.go
│   ├── db/                   # SQLite操作 (セグメント管理、ホスト管理、クリーンアップ処理)
│   │   ├── db.go
│   │   ├── segment.go
│   │   └── host.go
│   ├── kuma/                 # Uptime Kuma Socket.IO 連携＆同期クライアント
│   │   ├── client.go
│   │   └── sync.go           # 監視データインポート・競合チェックロジック
│   ├── notifier/             # 未確認端末検出時の Webhook 通知 (Slack / Discord / LINE / Teams)
│   │   └── webhook.go
│   ├── scanner/              # 低負荷ICMP Ping/mDNS/OUI スキャナー & 未登録端末検知
│   │   ├── scanner.go
│   │   ├── oui.go            # OUIデータ読み込み・ベンダー名解決ロジック
│   │   └── data/
│   │       └── oui.csv       # IEEE MA-L由来のOUI→ベンダー名 静的データ (go:embed対象)
│   ├── service/              # 自動起動・サービス管理 (systemd / launchd / Windows Service)
│   │   ├── service.go         # OS共通インターフェース定義
│   │   ├── service_linux.go   # systemd 実装 (ビルドタグ: linux)
│   │   ├── service_darwin.go  # launchd 実装 (ビルドタグ: darwin)
│   │   └── service_windows.go # Windows Service 実装 (ビルドタグ: windows, golang.org/x/sys/windows/svc)
│   └── web/                  # HTTPハンドラー、HTMXビュー(サイドバー/メイン)レンダリング
│       ├── handler.go
│       └── router.go
├── web/
│   ├── embed.go              # go:embed 定義
│   ├── static/               # CSS, JS (HTMX) 等の静的ファイル
│   └── template/             # HTMLテンプレート
│       ├── index.html        # 全体枠組み (2カラムレイアウト)
│       └── partials/
│           ├── sidebar.html  # セグメント一覧、設定、バージョン情報
│           ├── main_table.html # 選択中セグメントのホスト一覧テーブル
│           ├── action_menu.html # 三点リーダー (...) アクションメニュー仕様
│           ├── conflict_modal.html # 表示名競合解決モーダル
│           └── settings_modal.html # 設定画面モーダル
├── go.mod
├── go.sum
├── Makefile                  # クロスコンパイル・ビルドスクリプト
└── README.md
```

---

## 4. データベース設計 (SQLite)

### 4.1 セグメントテーブル (`segments`)
```sql
CREATE TABLE IF NOT EXISTS segments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(100) NOT NULL,          -- 表示名 (例: "本社LAN", "拠点VPN", "未分類")
    cidr VARCHAR(45) NOT NULL,            -- サブネット (例: "192.168.1.0/24", "10.8.0.0/24")
    interface_name VARCHAR(50),           -- 使用NIC/バインド設定 (任意)
    is_enabled BOOLEAN DEFAULT 1,
    is_default BOOLEAN DEFAULT 0,         -- 「未分類」予約セグメントを示すフラグ（削除不可）
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

**4.1.1 初期化・バリデーション補足**
* **「未分類」セグメントの自動作成**: DB初期化（マイグレーション）時に `is_default=1` の「未分類」セグメントを必ず1件シードする。Uptime Kumaのみに存在する監視対象（パターンC、9.1節）やスキャナーがセグメント未割当のホストを検出した場合はこのセグメントに割り当てる。`is_default=1` のセグメントはUIから削除不可とする。
* **CIDR重複バリデーション**: セグメント追加・編集時、既存の有効セグメント（`is_enabled=1`）とCIDR範囲が重複する場合は警告を表示する。重複自体を禁止はしないが、スキャン時の二重検出やホスト所属の曖昧さを避けるため、重複時はUI上で明示的に注意喚起する。
* **セグメント削除時の挙動**: セグメントを削除した場合、所属していたホストの `segment_id` は `NULL` になる（FK制約）。`NULL` は「未分類」セグムント（`is_default=1`）とは別の状態として扱い、UI上は「未分類」セグメントの一覧に集約して表示する。

### 4.2 ホストテーブル (`hosts`)
ホワイトリスト管理用の `is_approved`（承認フラグ）および自動削除保護用のフラグを保持します。

```sql
CREATE TABLE IF NOT EXISTS hosts (
    ip VARCHAR(45) PRIMARY KEY,
    segment_id INTEGER,                   -- 所属セグメントID
    mac_address VARCHAR(17),
    hostname VARCHAR(255),                -- 自動検出ホスト名 (mDNS/NBNS/PTR)
    vendor_model VARCHAR(255),            -- メーカー・モデル (OUI/UPnP)
    display_name VARCHAR(255),            -- 画面表示名
    os_vendor VARCHAR(255),               -- 推定OS
    status VARCHAR(10),                   -- 'up' | 'down'
    is_approved BOOLEAN DEFAULT 0,        -- 社内承認済み端末フラグ (0: 未承認/警告, 1: 承認済み)
    is_protected BOOLEAN DEFAULT 0,       -- 自動クリーンアップ保護フラグ (1: 期間経過でも削除しない)
    is_static_ip BOOLEAN DEFAULT 0,
    is_monitored BOOLEAN DEFAULT 0,
    is_paused BOOLEAN DEFAULT 0,
    has_conflict BOOLEAN DEFAULT 0,       -- 表示名の競合が発生しているかのフラグ
    kuma_name VARCHAR(255),               -- Uptime Kuma側の最新登録名（一時保持用）
    uptime_kuma_id INTEGER DEFAULT NULL,
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP, -- 初回検出日時
    last_seen DATETIME,
    FOREIGN KEY (segment_id) REFERENCES segments(id) ON DELETE SET NULL
);
```

### 4.2.1 ホスト識別モデル・IPアドレス再利用時の挙動【重要】

`ip` を主キーとしているため、DHCP環境でIPアドレスが別の物理端末に再割当てされた場合、**旧端末の承認状態 (`is_approved=1`) や保護設定を新しい（未知の）端末が引き継いでしまう**リスクがある。これはセキュリティ検知ツールとして致命的な誤検知（見逃し）につながるため、以下のルールで対処する。

* **MACアドレスを識別の第一情報源とする**: 同一IPに対し、DB上の `mac_address` と新たにスキャンで検出したMACアドレスが異なる場合、**別端末とみなし** `is_approved` を `0` にリセットし、`first_seen` を更新した上で未承認端末として再検出・Webhook通知を行う。
* **MACアドレス不明な区間の扱い**: リモートアクセスVPN等、L2情報（MACアドレス）が取得できないセグメントでは、IPアドレスのみを識別キーとせざるを得ない。この場合は `mac_address IS NULL` のホストに限り、IP一致のみで同一端末とみなす（既存の警戒レベルを維持）。
* **IPv4 / IPv6 のスコープ**: `ip` カラムは IPv6 表記（最大45文字）を許容する幅で定義しているが、v1.0時点での主要スキャン手段（ICMPv4 Ping, mDNS, NBNS）は主にIPv4を前提とする。IPv6ホストの自動検出は将来対応とし、v1.0では主にIPv4アドレスでの運用を想定する。

### 4.3 アプリ設定テーブル (`settings`)
クリーンアップ保持日数 (`retention_days`) や Webhook通知URL等を保持します。

```sql
CREATE TABLE IF NOT EXISTS settings (
    key VARCHAR(50) PRIMARY KEY,
    value TEXT                           -- 例: retention_days -> "180" (0で無効)
);
```

**初期値シード**: DB初期化時、`retention_days` は未設定時のデフォルト値として `"180"` を投入する。Webhook URL系キー（`webhook_slack_url` 等）は未設定 (`NULL`または空文字) で初期化し、未設定の通知チャネルへは送信をスキップする。`tls_cert_path` / `tls_key_path`（10.1節）も未設定で初期化し、未設定時は自己署名証明書を使用する。

### 4.4 ホワイトリスト台帳テーブル (`whitelist_entries`)
社内管理下にあるPC・端末台帳（ホスト名、MACアドレス、シリアル番号、所有者名等）を保持し、検出時の自動承認照合に利用します。

```sql
CREATE TABLE IF NOT EXISTS whitelist_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname VARCHAR(255),               -- 登録ホスト名 (照合用)
    mac_address VARCHAR(17),             -- 登録MACアドレス (照合用、任意)
    serial_number VARCHAR(100),          -- ハードウェアシリアル番号 (管理・メモ用)
    device_name VARCHAR(255),            -- 端末表示名 / 所有者名
    note TEXT,                           -- 備考 (部署、用途等)
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_whitelist_hostname ON whitelist_entries(hostname);
CREATE INDEX IF NOT EXISTS idx_whitelist_mac ON whitelist_entries(mac_address);
```

---

## 5. 古いホストの自動クリーンアップ（Retention Policy）仕様

DHCP環境等での動的IP割り当てや撤去済み機器によるデータベースの肥大化・ゴミデータの増加を防ぐため、**自動クリーンアップ機構**を実装します。

### 5.1 クリーンアップルール
* **判定基準**: 最終アクセス日時 (`last_seen`) から指定された日数（デフォルト: **180日**）が経過したホストを自動削除。
* **設定変更**: Web UIの設定画面より「30日 / 60日 / 90日 / 180日 / 365日 / 自動削除しない(無効)」を選択可能。

### 5.2 誤削除防止（保護ロジック）
以下のいずれかの条件に合致するホストは、`last_seen` が指定期間を超過していても**自動削除の対象から除外（保護）**します。

1. **`is_protected = 1`** (手動で「自動削除から保護」を設定した端末)
2. **`is_monitored = 1`** (Uptime Kuma で監視中のホスト)
3. **`is_static_ip = 1`** (固定IPとして管理されているホスト)
4. **`is_approved = 1`** (社内承認済みホワイトリスト端末 ※設定で除外ON/OFF可)

---

## 6. Web UI & セキュリティモニタリング仕様

画面は **2カラム構成（左: サイドバーナビゲーション / 右: メイン表示領域）** とします。

```text
+------------------------+-------------------------------------------------------+
|  lanmap [Logo/Title]   |  [Segment Name] 192.168.1.0/24   [🔄 同期] [Scan Now]  |
+------------------------+-------------------------------------------------------+
| ■ セグメント一覧        |  [ 🟢 オンラインのみ ]  [ 📋 すべて (過去ホスト表示) ] |
|   • すべてのホスト      |  +----+--------------+-------------------+----+------+----+  |
|   • 本社LAN (192.168..) |  | IP | ホスト名     | メーカー/モデル   |承認| 状態 |操作|  |
|   • 拠点VPN (10.8.0..) |  +----+--------------+-------------------+----+------+----+  |
|   • 未分類 (インポート) |  |    | taro-mbp     | Apple (MacBookPro)| 🟢 | 🟢   |... |  |
|   • [+ セグメント追加]  |  | ⚠️  | unknown-pc   | Unknown Vendor    | 🔴 | ⚪   |... │  |
|                        |  +----+--------------+-------------------+----+------+--│-+  |
| ---------------------- |                                                   │  |
| [⚙ 設定画面]          |                                 [... クリック] ─────┘  |
| v1.0.0                 |                                 ├─ ✅ 承認済みに変更   |
|                        |                                 ├─ 📌 削除保護を有効化 |
|                        |                                 ├─ ▶ 監視開始 (Kuma)   |
+------------------------+                                 └─ 🗑️ このホストを削除  |
```

### 6.1 メイン領域（ホスト一覧テーブル）構成

| 列 | 項目名 | 種別 | データ取得・セキュリティ挙動 |
|---|---|---|---|
| A | **IPアドレス** | 自動 | ICMP Ping / インポートから取得（未承認時は行をハイライト） |
| B | **ホスト名** | 自動 | mDNS / Reverse DNSから取得 |
| C | **表示名** | 手動 / 自動 | Uptime Kuma側の監視名。不一致時は ⚠️ 競合バッジ |
| D | **メーカー / モデル** | 自動 / 手動 | MACアドレス(OUI) / UPnP(SSDP) / mDNSから推定。自動推定できない、または誤推定の場合は `...` メニューから手動上書き可 |
| E | **OS** | 自動 | ICMP TTL値から推測 |
| F | **承認ステータス**| 手動 / 自動 | 🟢 承認済み / 🔴 **未承認 (要確認)** / 🆕 **NEW (24h以内)**。「NEW」はDB保存値ではなく `is_approved=0 AND first_seen >= now-24h` から都度算出する派生表示 |
| G | **ステータス** | 自動 | 🟢 up / ⚪ Down (`Last Seen` 併記) |
| H | **固定IP** | 手動 | 管理用チェックボックス（DB保存のみ） |
| I | **監視状態** | 自動表示 | 🟢 監視中 / ⏸️ 一時停止 / ⚪ 未監視 のバッジ |
| J | **操作** | UIボタン | 各行末の `...` アクションメニュー（ドロップダウン） |

**手動ホスト登録**: スキャン未検出の既知端末（例: 導入予定機器）をあらかじめ登録したい場合のため、サイドバーまたはメイン領域に「➕ ホストを手動追加」導線を設ける（IP・セグメント・表示名を手動入力し `hosts` に登録）。

---

## 7. アクションメニュー（`...` ボタン操作）仕様

各行末の **`...` ボタン** をクリックすることで展開されるアクションメニューから以下の操作を実行可能です。

1. **✅ 承認済みに変更 / 🔴 未承認に戻す (Toggle Approval)**: 
   * 社内端末として確認されたホストを「承認済み」へ切り替え（未承認アラート対象から除外）。
2. **📌 自動削除から保護 (Toggle Protection)**: 
   * `last_seen` が古くなっても自動クリーンアップで消えないよう保護対象に指定。
3. **▶ 監視開始 (Start Monitoring)**: 
   * Uptime Kuma へ `addMonitor` を送信し、監視を開始（未監視時のみ表示）。
4. **⏸️ 一時停止 / ▶ 再開 (Pause / Resume)**: 
   * Uptime Kuma へ `pauseMonitor` / `resumeMonitor` を送信。
5. **✏️ 表示名を変更 (Edit Display Name)**: 
   * ダイアログを開き名称変更。Uptime Kuma へ `editMonitor` を送信。
6. **🗑️ ホストを削除 / Kumaから削除 (Delete Host)**: 
   * 単体のホスト削除、または Uptime Kuma 連携削除（確認ダイアログ付き）。
7. **✏️ メーカー/モデルを手動編集 (Edit Vendor/Model)**:
   * OUI/UPnP等による自動推定が誤っている、または取得できなかった場合に手動で上書き。
8. **📌 保護解除 (Disable Protection)**:
   * 「📌 自動削除から保護」の逆操作。保護済みホストのメニューでは本項目に切り替わる（項目2とトグル表示）。

---

## 8. 未確認端末検出 & Webhook 即時アラート仕様

スキャン実行時、新しく未登録・未承認のMACアドレス/IPアドレスが検出された場合、以下のセキュリティ警戒フローを実行します。

```text
[LANスキャン実行] ──► [未承認MAC/IP検出] ──► [DB登録 (is_approved=0)]
                                                  │
                                                  ▼ (即時送信)
                                     [Webhook 通知エンジン]
                                                  │
                             ┌────────────────────┼────────────────────┐
                             ▼                    ▼                    ▼
                        [Slack]               [Discord]             [Teams/LINE]
```

### 8.1 通知の重複防止・再送ポリシー

未承認端末が同一スキャン周期を跨いで存在し続ける場合、スキャンの都度Webhookを再送すると通知が氾濫し「アラート疲れ」を招く。以下のルールで抑止する。

* **初回検出時のみ即時通知**: `hosts` レコードが新規作成された（＝新しいIP、またはIPは既知だがMACアドレス不一致により4.2.1節の識別ルールで別端末と判定された）タイミングでのみWebhookを送信する。
* **再送条件**: 一度通知済みの未承認端末について、`status` が `down` → `up` に復帰した場合（再出現）は再通知する。単に `is_approved=0` のまま存在し続けるだけでは再送しない。
* **通知抑制の解除**: `is_approved=1` に変更後、再び未承認相当の状態に戻ることは通常想定しない（MACアドレス不一致による別端末判定時を除く）ため、承認済みホストへの再通知は行わない。
* **フラッド対策**: 停電・大規模ネットワーク切断からの復旧直後など、単一スキャンで大量の新規未承認端末が同時検出された場合は、個別送信ではなく1回のWebhookに集約（バッチ通知）して送信する。

### 8.2 資産管理台帳（ホワイトリスト）CSV一括インポート & 自動照合承認仕様

社内PC・端末台帳（ホスト名、シリアル番号、MACアドレス等）のリストをあらかじめ登録しておくことで、スキャン検出時に自動照合して「承認済み」に昇格させ、台帳にない未知の端末のみをピンポイントでWebhookアラート通知する機能を提供します。

```text
[PC台帳 (CSV/TSV)] ──(一括インポート)──► [ホワイトリスト DB (whitelist_entries)]
                                                       │
[LANスキャン実行] ──► [ホスト検出 (IP/MAC/ホスト名)] ────┤
                                                       │
                      ┌────────────────────────────────┴────────────────────────────────┐
                      ▼                                                                 ▼
              【台帳と一致】 (ホスト名 または MAC一致)                          【台帳に存在しない】 (未知端末)
           ├─ 自動的に is_approved = 1 (承認済み)                            ├─ is_approved = 0 (未承認 ⚠️)
           ├─ display_name に所有者/端末名を自動反映                         └─ 🚨 Webhook 即時通知 (Slack/Teams等)
           └─ Webhook アラート通知をスキップ
```

1. **インポートフォーマット (CSV / TSV)**:
   * ヘッダー行あり/なし両対応。
   * 列構成: `ホスト名, MACアドレス(任意), シリアル番号(任意), 端末名/所有者(任意), 備考(任意)`
   * UI上のモーダル（`whitelist_modal.html`）からCSVファイルのドラッグ＆ドロップまたはテキストエリアへの直接貼り付けで一括投入可能。
2. **照合ルール**:
   * **ホスト名照合**: 検出された `hostname`（ドメイン部分を除去した短いホスト名含む）と台帳の `hostname` を大文字小文字を区別せず比較。
   * **MACアドレス照合**: 台帳に `mac_address` が記載されている場合、MACアドレス完全一致でも照合。
   * 一致時は `hosts` レコードの `is_approved` を `1`、`display_name` を台帳の `device_name`（または `hostname`）に自動設定。
3. **既存検出端末への即時適用**:
   * CSVインポート完了時、既にDBに存在する未承認端末に対しても即座にバックグラウンドで照合バッチを実行し、一致した端末を一括で「🟢 承認済み」へ更新する。

---

## 9. Uptime Kuma 双方向連携・同期仕様

```text
[Web UI (HTMX)] ──(HTTP)──> [lanmap] <──(Socket.IO 双方向)──> [Uptime Kuma]
```

### 9.1 照合・競合解決ルール

| パターン | 条件 | 処理 |
|---|---|---|
| **パターン A** | IP一致 / 表示名一致 | **自動接続**: `uptime_kuma_id` を紐付け、監視状態バッジを 🟢 監視中 に変更。 |
| **パターン B** | IP一致 / 表示名が異なる | **競合通知**: 該当行に `⚠️ 競合` バッジを表示。`...` メニューから名称上書き・同調を選択。 |
| **パターン C** | Uptime Kumaにのみ存在 | **自動インポート**: 該当IP・表示名で `hosts` テーブルに新規作成。「未分類」セグメントに割り当て。 |
| **パターン D** | `uptime_kuma_id` を持つホストが、Kuma側で当該モニターを削除済み | **リンク解除**: `uptime_kuma_id` を `NULL`、`is_monitored`/`is_paused` を `0` にリセットし、監視状態バッジを ⚪ 未監視 に戻す（`hosts` レコード自体は削除しない）。 |

### 9.2 同期実行タイミング

* **起動時同期**: lanmap起動時にUptime Kumaへ接続し、全モニター情報を取得して初回照合（パターンA〜D）を行う。
* **定期同期**: 以降はスキャン間隔と同様、バックグラウンドで定期的（デフォルト: スキャン間隔と同じ5〜15分）に再照合する。
* **手動同期**: UI右上の「🔄 同期」ボタン押下時にオンデマンドで即時再照合できる。
* **再接続**: Socket.IO接続が切断された場合は指数バックオフで再接続を試行し、再接続成功時に再照合を実行する。

### 9.3 認証方式（ログイン要否対応）

Uptime Kuma側の認証設定（Disable Auth 設定の有無）に応じて、以下の両方の接続モードに対応する。

* **認証未設定（Disable Auth）の場合**: Socket.IO接続確立後、ログイン処理を行わずそのままモニター情報取得・操作を行う。
* **認証設定あり（ユーザー名/パスワード）の場合**: 接続確立後、`settings` テーブルの `kuma_username` / `kuma_password` を用いて `login` イベントを送信し、認証成功後にモニター情報取得・操作を行う。認証失敗時は接続状態を「🔴 認証エラー」としてUI（設定画面）に表示し、以降の同期処理は認証情報が修正されるまで停止する。
* **設定項目**: `settings_modal.html` にUptime Kuma接続用の `URL` / `ユーザー名` / `パスワード`（任意入力、未入力なら認証未設定モードとして接続）入力欄を設ける。認証情報の暗号化保存は11.2ロードマップ項目4で対応。
* **2要素認証(2FA)**: v1.0では2FAが有効なUptime Kumaアカウントでの自動ログインは非対応とする（lanmap接続用アカウントは2FA無効を推奨、README等に明記）。

---

## 10. CLI / 起動・ポート・サービス管理仕様

```bash
# 通常起動 (フォアグラウンド)
$ lanmap

# サービス管理 (Linux: systemd / macOS: launchd / Windows: Windows Service (SCM))
$ lanmap service install
$ lanmap service start
$ lanmap service stop
$ lanmap service restart
$ lanmap service status
$ lanmap service uninstall
```

`service` サブコマンドは実行OSを自動判定し、Linuxでは`systemd`ユニット、macOSでは`launchd` plist、Windowsでは`golang.org/x/sys/windows/svc`によるサービス登録（SCM: Service Control Manager）を行う。2.5節の方針に従い、いずれのOSでもroot/Administrator専用ではない非特権ユーザーでの実行を既定とする（Windowsサービスのインストール操作自体はSCM登録のためAdministrator権限が必要だが、サービスの実行ユーザーは限定権限アカウントを指定可能とする）。

### 10.1 TLS / HTTPS通信

* **デフォルト動作（自己署名証明書）**: 初回起動時、`crypto/tls` / `crypto/x509` を用いてpure Goで自己署名証明書を自動生成し、常時 **HTTPS** で待受する（デフォルト: `https://localhost:3002`）。生成した証明書・秘密鍵はデータディレクトリ配下の `certs/cert.pem` / `certs/key.pem`（2.6節）に保存し、以降の起動では再利用する（有効期限が近い場合は自動再生成）。
* **カスタム証明書の指定**: 設定画面（`settings_modal.html`）からサーバー上に配置した証明書・秘密鍵ファイルのパスを指定すると、以降はそのファイルを `tls.LoadX509KeyPair` で読み込んで使用する。パスの組み合わせが不正な場合は設定画面でエラー表示し、既存の（自己署名）証明書での起動を維持する。
* **自己署名証明書によるブラウザ警告**: 社内LAN限定運用のため許容する。ただし初回アクセス時にUI側で「自己署名証明書の警告について」の簡単な案内を表示する。
* **設定値**: `settings` テーブルに `tls_cert_path` / `tls_key_path` キーを追加（未設定時は自己署名証明書を使用）。

### 10.2 ロギング & 終了処理

* **ロギング**: 標準出力へ構造化ログ（レベル: `INFO`/`WARN`/`ERROR`）を出力する。サービス運用時は systemd/launchd 経由で journald / ログファイルにリダイレクトされることを前提とする。ログレベルは環境変数（例: `LANMAP_LOG_LEVEL`）で変更可能とする。
* **グレースフルシャットダウン**: `SIGINT` / `SIGTERM` 受信時、実行中のスキャン処理・Uptime Kuma Socket.IO接続・HTTPサーバーを安全に終了させてからプロセスを終了する。

---

## 11. セキュリティモデル & 将来ロードマップ (Roadmap)

### 11.1 現在の想定・アクセス制御範囲 (Scope & Security Model)
* **通信プロトコル**: 信頼された社内LAN内での閉域運用を前提としつつ、通信内容自体は常時 **HTTPS**（デフォルトは自己署名証明書、10.1節）で暗号化します。VPN越しの拠点間通信も含め、経路上の盗聴に対する保護を初期バージョンから提供します。
* **アクセス制限**: 初期バージョンではアプリ層での認証機能を設けず、アクセス制御はネットワーク層（VPN、VLAN、防火壁等のアクセス制限）の保護機能に依存させます。

### 11.2 今後の機能拡張計画 (Roadmap)
1. **Web GUI パスワードロック機能 (簡易認証)**
   * 設定画面での管理者パスワード指定、およびセッションベースの簡易ログイン画面（認証ダイアログ/ロック機能）の追加。
2. **アクセス元IPの許可リスト（CIDR制限）**
   * 設定でアクセスを許可するIP/CIDRを指定し、それ以外からのリクエストをアプリ層で拒否する。ネットワーク層のアクセス制限に加え、アプリ側にも簡易ACLを持たせることで多層防御とする。
3. **CSRF対策**
   * 承認/削除/設定変更等、state変更を伴うHTMXリクエストにCSRFトークンを付与し、悪意あるサイトを踏んだブラウザ経由の意図しない操作を防ぐ。
4. **Webhook URL / Uptime Kuma認証情報の暗号化保存**
   * `settings` テーブルに平文で保持しているWebhook URLやKuma接続情報を暗号化し、DBファイル漏洩時の被害を抑える。
5. **簡易監査ログ**
   * 承認・削除・設定変更等の操作について、操作元IPと日時を記録し、事後追跡を可能にする。
6. **i18n（多言語）対応**
   * v1.0時点ではWeb UIの表示文言は日本語固定とする。将来対応として日本語・英語の2言語をサポートし、`web/template/` 配下のテンプレート文言を翻訳キー化した上で `web/i18n/<lang>.json`（or `.yaml`）等の翻訳リソースファイルとして `go:embed` で内包する。言語切替は設定画面での明示選択、またはブラウザの `Accept-Language` ヘッダーによる自動判定を検討する。翻訳キー追加を見越し、テンプレート側は初期段階から文言をハードコードせず翻訳関数（例: `{{ t "host.approve" }}`）経由で参照する設計にしておくと、後からの多言語化コストを抑えられる。
