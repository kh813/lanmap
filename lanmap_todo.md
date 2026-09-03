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

### 🔹 Phase 4: 内蔵 Ping 死活監視・24hタイムライン & 7日間推移集計エンジン (完全自立化)
- [x] **4.1 内蔵 Ping 履歴収集 & 統計エンジン (`internal/db/ping_history.go`)**
  * [x] ICMP Echo 定期測定結果の `ping_history` テーブル保存 & 自動パージ（7日間保持）
  * [x] 時間比例 24時間インライン SVG タイムライン生成（30分刻みスロット、未計測区間破線対応）
  * [x] 過去7日間の遅延推移 SVG 折れ線グラフ（日付目盛り・Min/Max ガイド線）
  * [x] 4時間毎×42ブロック稼働ヒートマップ & 稼働率(%)・ジッター(±ms)精密統計
  * [x] オンデマンド「⚡ 今すぐ Ping 診断」機能
  * [x] Uptime Kuma 外部依存の完全撤廃（単一バイナリ完全自己完結化）
- [x] **Phase 4 検証 & コミット**
  - [x] ビルド & モジュールテスト実行
  - [x] Git コミット

---

### 🔹 Phase 5: Web UI & HTMX フロントエンド
- [x] **5.1 テンプレート & 資材定義 (`web/`)**
  - [x] `web/embed.go` によるテンプレート・静的ファイルの `go:embed`
  - [x] 全体フレーム (`index.html`)
  - [x] パーシャルテンプレート作成 (`sidebar.html`, `main_table.html`, `action_menu.html`, `settings_modal.html`)
  - [x] `settings_modal.html`: 保持日数選択、Webhook URL入力（Google Chat/Slack/Discord/Teams/LINE）、TLS証明書パス入力欄
  - [x] `main_table.html`: 承認状態列の「NEW」バッジ算出表示（`is_approved=0` かつ `first_seen` 24時間以内）(仕様 6.1)
  - [x] ホスト手動追加フォーム（IP/セグメント/表示名入力、CIDR/IP形式バリデーション）(仕様 6.1)
  - [x] セグメント追加フォームのCIDR形式・重複バリデーション表示 (仕様 4.1.1)
- [x] **5.2 HTTP ハンドラー & HTMX ルーティング (`internal/web`)**
  - [x] HTTP ルーティング構築 (`router.go`)
  - [x] メイン画面・セグメント切替・オンラインフィルタリングハンドラー (`handler.go`)
  - [x] 三点リーダー (`...`) メニューアクションハンドラー (承認トグル, 削除保護トグル, メーカー/モデル手動編集, 表示名変更, ホスト削除)
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
  - [x] `SIGINT`/`SIGTERM` 受信時のグレースフルシャットダウン（スキャン/HTTPサーバーの安全停止）(仕様 10.2)
- [x] **6.4 Makefile & ドキュメント**
  - [x] `Makefile` (ビルド・クロスコンパイル設定、Windows/macOS/Linux)
  - [x] `README.md` 更新
- [x] **Phase 6 最終検証 & コミット**
  - [x] 全体ビルド & 総合テスト実行（Windows/macOS/Linux クロスコンパイル確認含む）
  - [x] E2E統合シナリオ確認（スキャン検出→未承認DB登録→Webhook通知→UI表示→承認操作の一連の流れ）
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

---

### 🔹 Phase 11: GitHub Releases 自動セルフアップデート機能
- [x] **11.1 アップデータ層 (`internal/updater`)**
  - [x] GitHub Releases API 照会 & バージョン比較判定 (`updater.go`)
  - [x] OS/アーキテクチャ別 ZIP アセットのストリーミングダウンロード & 解凍
  - [x] 実行中バイナリの安全なインプレースアトミック置換（Unix: rename / Windows: `.old` 退避）
  - [x] バックグラウンド自己再起動処理 (`RestartSelf`)
  - [x] 単体テスト作成 & 実行 (`internal/updater/updater_test.go`)
- [x] **11.2 CLI サブコマンド (`cmd/lanmap/main.go`)**
  - [x] `lanmap update` / `lanmap upgrade` コマンド実装
- [x] **11.3 Web UI & API (`internal/web`)**
  - [x] `GET /api/system/update/check` エンドポイント & htmx 連携
  - [x] `POST /api/system/update/apply` エンドポイント & 5秒後自動リロード
  - [x] 設定モーダル (`settings_modal.html`) にセルフアップデートセクション追加
  - [x] サイドバー (`sidebar.html`) のバージョンバッジクリック導線改善
- [x] **11.4 検証 & コミット**
  - [x] 単体テスト実行 (`go test -v ./internal/updater/... ./internal/web/...`)
  - [x] Git コミット

---

### 🔹 Phase 12: ホスト行クリック詳細モーダル & 7日間 Ping 推移・オンデマンド Ping 診断
- [x] **12.1 DB & SVG チャート層 (`internal/db/ping_history.go`)**
  - [x] 7日間専用 SVG スパークライン描画 (`RenderSparkline7dSVG`: X軸日付目盛り、Min/Maxガイド線、未計測破線)
  - [x] 7日間 Uptime ブロック描画 (`RenderUptimeBlocks7dSVG`: 4時間毎の42スロットヒートマップ)
  - [x] 7日間詳細統計計算 (`ComputePingStats7dDetails`: 稼働率、平均/最小/最大RTT、ジッター、総プローブ数)
  - [x] 単体テスト作成 & 実行 (`internal/db/db_test.go`)
- [x] **12.2 Web ハンドラー & ルーティング (`internal/web`)**
  - [x] `GET /modals/host_detail` エンドポイント実装 (`handler.go`, `router.go`)
  - [x] `POST /api/hosts/{ip}/ping_test` オンデマンド即時 Ping 診断エンドポイント実装
  - [x] Web 単体テスト追加 & 実行 (`internal/web/web_test.go`)
- [x] **12.3 Web UI テンプレート (`web/template`)**
  - [x] `web/template/partials/host_detail_modal.html` 作成（7日間グラフ、ヒートマップ、統計カード、端末プロファイル、即時Pingボタン）
  - [x] `web/template/partials/main_table.html` 各行に `hx-get="/modals/host_detail?ip={{.IP}}"` を付与
  - [x] 行内要素（チェックボックス、競合ボタン、アクションメニュー）に `stopPropagation` を適用して誤発火ガード
  - [x] テーブル上部にヒントガイドバナー設置
- [x] **12.4 ドキュメント包括的更新**
  - [x] `README.md` 更新（セルフアップデート、詳細モーダル、CLIコマンド）
  - [x] `lanmap_design.md` 更新（セルフアップデート仕様、ロードマップ完了反映）
  - [x] `lanmap_todo.md` 更新（全フェーズ反映）

---

### 🔹 Phase 13: マルチNIC・仮想NIC安全スキャン & サイドバー3点リーダー操作
- [x] **13.1 スキャナー & ネットワーク検出層 (`internal/scanner`)**
  - [x] `GetDefaultGatewayLocalIP()` によるOSルーティングテーブル照会（Default Gateway判定）
  - [x] `DetectLocalNetworks()` による全物理・仮想NICの検出と `IsDefault` 付与
  - [x] `EnsureLocalSegmentAutoRegistered()` で Default Gateway のみ `is_enabled=true`、他NICは安全のため `is_enabled=false` で自動登録
  - [x] 単体テスト作成 & 実行 (`internal/scanner/scanner_test.go`)
- [x] **13.2 Web API & ハンドラー (`internal/web`)**
  - [x] `POST /api/segments/{id}/toggle` セグメントスキャン有効/無効トグルAPI実装
  - [x] `GET /partials/segment_menu` セグメント行アクションメニューAPI実装
  - [x] Web 単体テスト追加 & 実行 (`internal/web/web_test.go`)
- [x] **13.3 Web UI テンプレート (`web/template`)**
  - [x] `web/template/partials/segment_menu.html` 新規作成（スキャン追加/停止、名前編集、削除）
  - [x] `web/template/partials/sidebar.html` セグメントループ改修（停止中セグメントのグレーアウト表示、3点リーダーボタン設置、未登録NIC件数バッジ表示）
  - [x] `web/template/partials/segment_modal.html` 改修（未登録/削除済みNICのサジェストカード、ワンクリック再追加、フォーム自動反映）
- [x] **13.4 ドキュメント更新**
  - [x] `README.md`、`lanmap_design.md`、`lanmap_todo.md` 更新

---

### 🔹 Phase 14: 各セグメントの DHCP IPレンジ設定 & 動的IP端末の視覚的区別
- [x] **14.1 データベース層 (`internal/db`)**
  - [x] `segments` テーブルに `dhcp_range VARCHAR(100)` カラム追加およびマイグレーション
  - [x] `hosts` テーブルに `is_dhcp BOOLEAN DEFAULT 0` カラム追加およびマイグレーション
  - [x] `Segment` 構造体に `DHCPRange` 追加、`CreateSegmentWithDHCP` / `GetSegment` / `ListSegments` / `UpdateSegment` 実装
  - [x] `IsInDHCPRange(ip, range)`（オクテット指定・フルIP指定・カンマ区切り対応）実装
  - [x] `GuessDHCPRange(hosts, cidr)` によるWi-Fi/クライアント端末のIP分布からのDHCP帯域自動推定
  - [x] `ToggleHostDHCP(ip)` および `AutoAdjustSegmentDHCPRange(segID)` 実装（`is_dhcp_manual` 時の自動調整スキップ対応）
  - [x] `IsInDHCPRange` の複数レンジ判定対応（カンマ、改行、セミコロン区切り）
  - [x] `ValidateDHCPRange(dhcpRange, cidr)` によるDHCPレンジの記法・範囲・サブネット整合性検証
  - [x] `Segment` 構造体およびテーブルに `is_dhcp_manual BOOLEAN DEFAULT 0` カラム追加
  - [x] `Host` 構造体に `IsDHCP bool` フィールド追加
  - [x] DB単体テスト作成 & 実行 (`TestDHCPRangeAndGuess`, `TestToggleHostDHCP`, `TestValidateDHCPRange` in `internal/db/db_test.go`)
- [x] **14.2 Web API & ハンドラー (`internal/web`)**
  - [x] `POST /api/hosts/{ip}/toggle_dhcp` API実装（DHCPフラグ反転＆セグメントDHCPレンジ自動調整）
  - [x] `HandleSegmentModal` で端末分布から推定された `SuggestedDHCP` をテンプレートに供給
  - [x] `HandleCreateOrUpdateSegment` で `ValidateDHCPRange` による保存前バリデーション＆エラー表示処理実装
  - [x] `HandleCreateOrUpdateSegment` で `dhcp_range` および `is_dhcp_manual` の保存処理実装
  - [x] `HandleMainTablePartial` で CIDR フォールバック判定を導入し、`segment_id` が未設定の端末でも確実に `host.IsDHCP` を判定・付与
  - [x] Web 単体テスト追加 & 実行 (`TestSegmentDHCPValidation` in `internal/web/web_test.go`)
- [x] **14.3 Web UI テンプレート (`web/template`)**
  - [x] `segment_menu.html` の編集ボタンの onclick 不具合（同期消滅によるリクエスト阻害）を修正し、セグメント編集モーダルが確実に表示されるように改善
  - [x] `segment_modal.html` に DHCP IPレンジ複数指定説明、手入力固定チェックボックス (`seg_is_dhcp_manual`) 設置
  - [x] `segment_modal.html` にエラー表示コンテナ設置およびバリデーションエラー時の安全なモーダル開閉制御
  - [x] `action_menu.html` に「🟢 DHCP動的端末としてマーク / 🔌 固定IPに変更」項目を追加
  - [x] `main_table.html` 改修：
    - [x] 行背景: DHCP動的端末は赤色ハイライトから除外（日常利用端末のアラート疲れ防止）
    - [x] IP横アイコン: 固定IP帯未承認端末は `⚠️`（警戒）、DHCP端末は `🟢`（自動許可・DHCP動的識別）
    - [x] 承認列バッジ: `🟢 DHCP 🆕`（新規・自動許可）、`🟢 DHCP動的`（既存・自動許可）
- [x] **14.4 ドキュメント更新**
  - [x] `README.md`、`lanmap_design.md`、`lanmap_todo.md` 更新

---

### 🔹 Phase 15: i18n 国際化・多言語対応 (デフォルト英語 & ブラウザ言語自動切替 & EN/JP スイッチャー)
- [x] **15.1 i18n 辞書 & 言語判定パッケージ (`internal/i18n`)**
  - [x] `DetectLanguage(r)`: Cookie (`lanmap_lang`) ➔ クエリパラメータ (`?lang=`) ➔ `Accept-Language` ヘッダー ➔ デフォルト英語 (`en`) の優先順位判定
  - [x] `T(lang, key)` / `TF(lang, key, args...)`: キー翻訳 & `fmt.Sprintf` フォーマット関数
  - [x] 英語（EN）/ 日本語（JA）全UIキー定義（テーブル、サイドバー、アクションメニュー、各モーダル、バッジ、ツールチップ）
  - [x] 単体テスト & 辞書キー整合性テスト作成 (`internal/i18n/i18n_test.go`)
- [x] **15.2 Web ハンドラー & テンプレートエンジン (`internal/web`)**
  - [x] テンプレート FuncMap に `t` (`i18n.T`)、`tf` (`i18n.TF`)、`safeHTML` を登録
  - [x] 全ハンドラーでコンテキストに `Lang: i18n.DetectLanguage(r)` を付与
  - [x] `POST /api/set_language`: Cookie `lanmap_lang` 設定および `HX-Refresh: true` レスポンス実装
  - [x] Web 単体テスト追加 & 実行 (`internal/web/web_test.go`: デフォルト英語検証、日本語Accept-Language検証、Cookieオーバーライド検証)
- [x] **15.3 フロントエンド & UI テンプレート改修 (`web/template`)**
  - [x] `index.html`: 動的 `<html lang="...">` 属性、動的 `<title>`、`changeLanguage(lang)` JS ヘルパー
  - [x] `main_table.html`: 右上に `[ EN | JP ]` トグルスイッチ設置、各列ヘッダー・アクションボタン・バッジ・ポップオーバー・検索スクリプトの i18n 化
  - [x] `sidebar.html`: セグメント一覧、未登録NICバッジ、テーマ切替ツールチップ、設定ボタン等の i18n 化
  - [x] `action_menu.html`: 承認トグル、削除保護、DHCPマーク、編集、削除項目の i18n 化
  - [x] `segment_menu.html`: スキャン一時停止/再開、セグメント編集、削除項目の i18n 化
  - [x] `add_host_modal.html` & `edit_host_modal.html`: フォーム項目・チェックボックス・ボタンの i18n 化
  - [x] `segment_modal.html`: 未登録NICカード、CIDR/DHCP説明文、手動固定チェックボックス、プリセットボタン等の i18n 化
  - [x] `settings_modal.html`: システム設定、保持期間、Webhook通知設定、証明書設定、セルフアップデート等の i18n 化
  - [x] `host_detail_modal.html`: 7日間Ping推移見出し、各メトリクスカード、デバイスプロファイル項目の i18n 化
  - [x] `whitelist_modal.html`: 端末台帳モーダル、CSVインポートフォーム、一覧テーブルの i18n 化
- [x] **15.4 ドキュメント更新**
  - [x] `README.md`、`lanmap_design.md`、`lanmap_todo.md` 更新

