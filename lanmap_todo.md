# lanmap (lmap) 実装 ToDo リスト & フェーズ計画

本ドキュメントは `lanmap_design.md` の仕様に基づいた開発フェーズごとの ToDo リストです。

---

## 📋 全体開発フロー規約

1. **フェーズ毎の実装完了確認**: 各タスクの実装後、該当モジュールの動作確認・単体テストを実装する。
2. **ビルド & テスト実行**: 
   ```bash
   go test -v ./...
   go build -o lmap ./cmd/lanmap
   ```
3. **エラー修正**: ビルドエラー、コンパイル警告、テスト失敗が発生した場合は直ちに修正する。
4. **コミット**: 成功確認後、`git commit -m "feat(phase-X): ..."` で変更をコミットする。

---

## 🚀 フェーズ別 ToDo リスト

### 🔹 Phase 1: プロジェクト基盤・設定 & SQLite DB層
- [x] **1.1 モジュール初期化 & 依存ライブラリ設定**
  - [x] `go.mod` 初期化
  - [x] `modernc.org/sqlite` の追加
  - [x] `golang.org/x/net/icmp` の追加
  - [x] `github.com/breml/go-uptime-kuma-client` の追加 (仕様 2.2、`graarh/golang-socketio`は不採用)
  - [x] `golang.org/x/sys` の追加 (Windowsサービス管理用、仕様 2.2)
- [x] **1.2 設定管理 (`internal/config`)**
  - [x] ポート、スキャン間隔、並列数制限等の設定構造体定義 (`config.go`)
  - [x] 環境変数 / デフォルト値の読み込みロジック
  - [x] データディレクトリ解決ロジック（既定: 実行ファイルと同じディレクトリ、`LANMAP_DATA_DIR` 環境変数で上書き可、`certs/` サブディレクトリを含め初回起動時に自動作成）(仕様 2.6)
- [x] **1.3 SQLite DB操作 (`internal/db`)**
  - [x] SQLite 接続処理 & スキーマ自動マイグレーション (`db.go`)
  - [x] セグメント用 CRUD (`segment.go`: `segments` テーブル、CIDR重複チェック、`is_default`削除禁止バリデーション含む)
  - [x] 初期化時シード処理: `is_default=1` の「未分類」セグメント作成、`settings.retention_days` デフォルト値(`"180"`)投入 (仕様 4.1.1 / 4.3)
  - [x] ホスト用 CRUD & ステータス更新 (`host.go`: `hosts` テーブル)
  - [x] ホスト識別ロジック: 同一IPでMACアドレス不一致検出時に別端末として扱い `is_approved`/`first_seen` をリセットする処理 (仕様 4.2.1)
  - [x] アプリ設定 CRUD (`settings` テーブル)
  - [x] 自動クリーンアップ（Retention Policy）判定・削除保護ロジック (`is_protected`, `is_monitored`, `is_static_ip`, `is_approved`)
  - [x] クリーンアップ保護ロジックの組み合わせテスト（4条件それぞれ単独/複合での除外確認）
- [x] **Phase 1 検証 & コミット**
  - [x] ビルド & 単体テストの実行 (`go test ./internal/db/...`)
  - [x] Git コミット

---

### 🔹 Phase 2: スキャナー & 低負荷ネットワーク検出エンジン
- [x] **2.1 ネットワークスキャナー (`internal/scanner`)**
  - [x] ICMP Ping による並列数制限付き IP スキャン（非特権データグラムソケット優先、OS別実装: Linux/macOSは`golang.org/x/net/icmp`の`udp4`/`udp6`、Windowsは`IcmpSendEcho`。送信失敗時は生ソケットへフォールバックせず対処法をログ表示）(仕様 2.5)
  - [x] ホスト名・ネットワーク情報収集 (mDNS, NBNS, UPnP/SSDP)
  - [x] OUIデータ (`internal/scanner/data/oui.csv`) の取得・同梱 & `go:embed` によるベンダー名解決ロジック (`oui.go`) (仕様 2.4)
  - [x] ICMP TTL からの OS 推定ロジック
  - [x] 新規端末 / 未承認端末検出判定 & `hosts` DB 登録（MACアドレス不一致時の別端末判定を含む、仕様 4.2.1）
  - [x] セグメント未割当ホストの「未分類」セグメントへの自動割当
- [x] **Phase 2 検証 & コミット**
  - [x] ビルド & スキャナー単体テスト実行
  - [x] Git コミット

---

### 🔹 Phase 3: Webhook 通知エンジン
- [x] **3.1 Webhook 通知モジュール (`internal/notifier`)**
  - [x] Webhook ペイロード生成処理 (`webhook.go`)
  - [x] Slack / Discord / Teams / LINE 形式へのフォーマット変換（各プラットフォームのペイロード形式に沿ったテスト含む）
  - [x] 未承認端末検出時の非同期 Webhook 即時送信処理
  - [x] 通知の重複防止・再送ポリシー実装（初回検出のみ即時通知、down→up復帰時のみ再送、既存未承認の連続検出では再送しない）(仕様 8.1)
  - [x] 大量新規端末同時検出時のバッチ通知（フラッド対策）(仕様 8.1)
  - [x] Webhook送信失敗時のリトライ/タイムアウト処理
  - [x] 未設定のWebhook URLに対する送信スキップ処理
- [x] **Phase 3 検証 & コミット**
  - [x] ビルド & Webhook 通知テスト実行
  - [x] Git コミット

---

### 🔹 Phase 4: Uptime Kuma Socket.IO 双方向連携
- [x] **4.1 Socket.IO クライアント & 同期処理 (`internal/kuma`)**
  - [x] `breml/go-uptime-kuma-client` を用いた Uptime Kuma Socket.IO 接続処理 (`client.go`)
  - [x] 認証未設定/認証設定あり（ユーザー名・パスワードによる`login`イベント）両モードへの対応、認証失敗時のエラー状態表示 (仕様 9.3)
  - [x] 切断時の指数バックオフによる再接続処理 (仕様 9.2)
  - [x] モニター情報の取得・自動インポート・照合ロジック (`sync.go`)
  - [x] 照合パターン（パターン A: 一致、パターン B: 表示名競合 ⚠️、パターン C: 新規インポート、パターン D: Kuma側削除によるリンク解除）の実装 (仕様 9.1)
  - [x] 起動時同期・定期同期（バックグラウンドタイマー）・手動同期（UIトリガー）の実装 (仕様 9.2)
  - [x] Kuma アクション連動 (`addMonitor`, `pauseMonitor`, `resumeMonitor`, `editMonitor`, `deleteMonitor`)
- [x] **Phase 4 検証 & コミット**
  - [x] ビルド & モジュールテスト実行
  - [x] Git コミット

---

### 🔹 Phase 5: Web UI & HTMX フロントエンド
- [x] **5.1 テンプレート & 資材定義 (`web/`)**
  - [x] `web/embed.go` によるテンプレート・静的ファイルの `go:embed`
  - [x] 全体フレーム (`index.html`)
  - [x] パーシャルテンプレート作成 (`sidebar.html`, `main_table.html`, `action_menu.html`, `conflict_modal.html`, `settings_modal.html`)
  - [x] `settings_modal.html`: 保持日数選択、Webhook URL入力（Slack/Discord/Teams/LINE）、Uptime Kuma接続情報（URL / ユーザー名 / パスワード、いずれも未入力可＝認証未設定モード）入力欄 (仕様 9.3)
  - [x] `main_table.html`: 承認状態列の「NEW」バッジ算出表示（`is_approved=0` かつ `first_seen` 24時間以内）(仕様 6.1)
  - [x] ホスト手動追加フォーム（IP/セグメント/表示名入力、CIDR/IP形式バリデーション）(仕様 6.1)
  - [x] セグメント追加フォームのCIDR形式・重複バリデーション表示 (仕様 4.1.1)
  - [x] `conflict_modal.html`: 表示名競合時の「lanmap側を採用」/「Kuma側を採用」選択・同調アクション
- [x] **5.2 HTTP ハンドラー & HTMX ルーティング (`internal/web`)**
  - [x] HTTP ルーティング構築 (`router.go`)
  - [x] メイン画面・セグメント切替・オンラインフィルタリングハンドラー (`handler.go`)
  - [x] 三点リーダー (`...`) メニューアクションハンドラー (承認トグル, 削除保護トグル, メーカー/モデル手動編集, 表示名変更, Kuma監視開始/一時停止/削除)
  - [x] ホスト手動追加・セグメント追加/編集/削除ハンドラー（`is_default`セグメント削除拒否含む）
- [x] **Phase 5 検証 & コミット**
  - [x] ビルド & UI/サーバー起動動作検証
  - [x] Git コミット

---

### 🔹 Phase 6: CLI, サービス管理, メインエントリポイント & 総合検証
- [x] **6.1 バックグラウンドサービス管理 (`internal/service`)**
  - [x] OS共通インターフェース定義 (`service.go`)
  - [x] `systemd` サービス定義自動生成 & インストール/アンインストール/起動/停止コマンド (`service_linux.go`) (仕様 2.5, 10)
  - [x] `launchd` plist自動生成 & インストール/アンインストール/起動/停止コマンド (`service_darwin.go`) (仕様 2.5, 10)
  - [x] `golang.org/x/sys/windows/svc` を用いたWindows Service登録・インストール/アンインストール/起動/停止コマンド (`service_windows.go`) (仕様 2.2, 10)
  - [x] いずれのOSでも非特権ユーザーでの実行をデフォルトとする設定 (仕様 2.5)
- [x] **6.2 TLS / HTTPS対応 (`internal/config`, `internal/web`)**
  - [x] 自己署名証明書の自動生成処理（`crypto/tls`/`crypto/x509`、`<データディレクトリ>/certs/` への保存・再利用・有効期限切れ前の自動再生成）(仕様 2.6, 10.1)
  - [x] `settings.tls_cert_path` / `tls_key_path` が指定された場合の `tls.LoadX509KeyPair` 読み込み・バリデーション（不正時は既存証明書へフォールバック）(仕様 10.1)
  - [x] `ListenAndServeTLS` へのサーバー起動切り替え（デフォルトポート `https://localhost:3002`）
  - [x] `settings_modal.html` へのTLS証明書パス入力欄追加 (仕様 10.1, Phase 5と連携)
- [x] **6.3 エントリポイント & CLI (`cmd/lanmap/main.go`)**
  - [x] CLI 引数解析 (通常起動 / `service` サブコマンド / `version`)
  - [x] 定期スキャンタスク & クリーンアップタスクのバックグラウンド起動
  - [x] 構造化ロギング実装（`INFO`/`WARN`/`ERROR`、`LANMAP_LOG_LEVEL` 環境変数対応）(仕様 10.2)
  - [x] `SIGINT`/`SIGTERM` 受信時のグレースフルシャットダウン（スキャン/Kuma接続/HTTPサーバーの安全停止）(仕様 10.2)
- [x] **6.4 Makefile & ドキュメント**
  - [x] `Makefile` (ビルド・クロスコンパイル設定、Windows/macOS/Linux)
  - [x] `README.md` 更新
- [x] **Phase 6 最終検証 & コミット**
  - [x] 全体ビルド & 総合テスト実行（Windows/macOS/Linux クロスコンパイル確認含む）
  - [x] E2E統合シナリオ確認（スキャン検出→未承認DB登録→Webhook通知→UI表示→承認操作→Kuma監視開始の一連の流れ）
  - [x] 最終 Git コミット

---

### 🔹 Phase 7: 資産管理台帳（ホワイトリスト）CSV一括インポート & 自動照合承認機能
- [x] **7.1 DB層 (`internal/db`)**
  - [x] `whitelist_entries` テーブル定義 & マイグレーション (`db.go`)
  - [x] ホワイトリスト登録・一覧取得・個別削除・一括削除 CRUD (`whitelist.go`)
  - [x] 検出ホストのホワイトリスト照合ロジック (`MatchWhitelist(hostname, mac) (*WhitelistEntry, bool)`)
  - [x] 既存未承認ホストに対する一括再照合バッチ (`ReconcileHostsWithWhitelist()`)
- [x] **7.2 スキャナー連動 (`internal/scanner`)**
  - [x] スキャン検出時にホワイトリストと照合し、一致した場合は `is_approved = true` / 表示名自動補完
  - [x] ホワイトリストに存在しない端末のみを未承認アラート（Webhook）対象とする
- [x] **7.3 Web UI & HTMX ハンドラー (`web/`, `internal/web`)**
  - [x] `web/template/partials/whitelist_modal.html` 作成（CSV一括インポート、テキスト直接入力、登録台帳リスト表示・削除）
  - [x] サイドバーまたは設定画面に「📋 台帳ホワイトリスト登録」導線追加
  - [x] `/modals/whitelist`, `/api/whitelist/import`, `/api/whitelist/{id}` ルーティング & ハンドラー
- [x] **7.4 検証 & コミット**
  - [x] 単体テスト実行 (`go test -v ./...`)
  - [x] サーバー起動確認 & Git コミット

---

### 🔹 Phase 8: ブロードキャストストーム & 異常トラフィック検知機能
- [x] **8.1 DB層 (`internal/db`)**
  - [x] `hosts` テーブルに `broadcast_count_1m`, `is_storming` カラム追加 (`db.go`, `host.go`)
  - [x] `UpdateHostBroadcastStats(ip string, count1m int, isStorming bool)` 実装
- [x] **8.2 パケットリスナー & モニター層 (`internal/monitor/broadcast.go`)**
  - [x] バックグラウンド UDP ブロードキャストリスナーの実装 (ポート 137, 1900, 5353, 67/68, 0 等)
  - [x] 1分間のスライディングウィンドウ集計 & 閾値 (120 pkt/min) 判定
  - [x] 異常ホストのDB更新および Webhook 即時アラート連動
- [x] **8.3 Webhook 通知連動 (`internal/notifier`)**
  - [x] `NotifyBroadcastStorm(ctx, host, pktCount)` 実装 (Slack, Discord, Teams, LINE)
- [x] **8.4 Web UI 表示 (`web/template/partials/main_table.html`)**
  - [x] ホスト一覧での「💥 ブロードキャスト過多」警告バッジ & 行ハイライト
- [x] **8.5 検証 & コミット**
  - [x] 単体テスト作成 & 実行 (`go test -v ./...`)
  - [x] サーバー起動確認 & Git コミット

---

### 🔹 Phase 9: オープンポート検知 & ホスト詳細ホバーカード機能
- [x] **9.1 DB層 (`internal/db`)**
  - [x] `hosts` テーブルに `open_ports` カラム追加 (`db.go`, `host.go`)
  - [x] `OpenPortsList() []PortInfo` ヘルパーメソッド実装
- [x] **9.2 スキャナー層 (`internal/scanner`)**
  - [x] 主要ポート（21, 22, 53, 80, 443, 445, 548, 554, 631, 3389, 5000, 8008, 8080等）の軽量プローブエンジン (`ports.go`)
  - [x] スキャン時に `ScanOpenPorts(ip)` を実行し `open_ports` を保存
- [x] **9.3 Web UI (`web/template/partials/main_table.html`)**
  - [x] マウスホバー時にオープンポート・通信状況・詳細を表示するポップオーバーカード実装
- [x] **9.4 検証 & コミット**
  - [x] 単体テスト作成 & 実行 (`go test -v ./...`)
  - [x] サーバー起動確認 & Git コミット

---

### 🔹 Phase 10: 拡張ホストプロファイリング & 品質メトリクス (5大機能)
- [x] **10.1 DB層 (`internal/db`)**
  - [x] `hosts` テーブルに `http_title`, `upnp_name`, `upnp_model`, `upnp_serial`, `tls_subject`, `tls_expiry`, `mdns_model`, `ping_jitter_ms`, `uptime_pct` カラム追加 (`db.go`, `host.go`)
  - [x] `TLSExpiresSoon() bool`, `TLSFormatted() string`, `JitterFormatted() string` 等のヘルパーメソッド実装
- [x] **10.2 スキャナー・プローブ層 (`internal/scanner`)**
  - [x] Feature 1: HTTP/HTTPS `<title>` 抽出 (`web_title.go`)
  - [x] Feature 2: UPnP / SSDP XML 解析 (`upnp.go`)
  - [x] Feature 3: TLS サーバー証明書 (X.509) 有効期限 & Subject 解析 (`tls_cert.go`)
  - [x] Feature 4: mDNS TXT レコード (Apple/IoTモデル) 解析 (`mdns_model.go`)
  - [x] Feature 5: Ping ジッター & 24h 稼働率計算 (`jitter.go`)
  - [x] `scanner.go` への全プローブ統合
- [x] **10.3 Web UI (`web/template/partials/main_table.html`)**
  - [x] ホスト詳細ホバーカードに Webタイトル, UPnP型番/シリアル, mDNSモデル, TLS証明書有効期限/警告, ジッター/稼働率を表示
- [x] **10.4 検証 & コミット**
  - [x] 単体テスト作成 & 実行 (`go test -v ./...`)
  - [x] サーバー起動確認 & Git コミット
