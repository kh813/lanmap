# lanmap (lmap) 実装 ToDo リスト & フェーズ計画

本ドキュメントは `lanmap_design_final.md` の仕様に基づいた開発フェーズごとの ToDo リストです。
各フェーズ完了時には必ず **ビルド (`go build`) とテスト (`go test`) を実行し、エラーを修正した上で git コミット** を行います。

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
- [ ] **1.1 モジュール初期化 & 依存ライブラリ設定**
  - [ ] `go.mod` 初期化
  - [ ] `modernc.org/sqlite` の追加
  - [ ] `golang.org/x/net/icmp` の追加
  - [ ] `github.com/breml/go-uptime-kuma-client` の追加 (仕様 2.2、`graarh/golang-socketio`は不採用)
  - [ ] `golang.org/x/sys` の追加 (Windowsサービス管理用、仕様 2.2)
- [ ] **1.2 設定管理 (`internal/config`)**
  - [ ] ポート、スキャン間隔、並列数制限等の設定構造体定義 (`config.go`)
  - [ ] 環境変数 / デフォルト値の読み込みロジック
  - [ ] データディレクトリ解決ロジック（既定: 実行ファイルと同じディレクトリ、`LANMAP_DATA_DIR` 環境変数で上書き可、`certs/` サブディレクトリを含め初回起動時に自動作成）(仕様 2.6)
- [ ] **1.3 SQLite DB操作 (`internal/db`)**
  - [ ] SQLite 接続処理 & スキーマ自動マイグレーション (`db.go`)
  - [ ] セグメント用 CRUD (`segment.go`: `segments` テーブル、CIDR重複チェック、`is_default`削除禁止バリデーション含む)
  - [ ] 初期化時シード処理: `is_default=1` の「未分類」セグメント作成、`settings.retention_days` デフォルト値(`"180"`)投入 (仕様 4.1.1 / 4.3)
  - [ ] ホスト用 CRUD & ステータス更新 (`host.go`: `hosts` テーブル)
  - [ ] ホスト識別ロジック: 同一IPでMACアドレス不一致検出時に別端末として扱い `is_approved`/`first_seen` をリセットする処理 (仕様 4.2.1)
  - [ ] アプリ設定 CRUD (`settings` テーブル)
  - [ ] 自動クリーンアップ（Retention Policy）判定・削除保護ロジック (`is_protected`, `is_monitored`, `is_static_ip`, `is_approved`)
  - [ ] クリーンアップ保護ロジックの組み合わせテスト（4条件それぞれ単独/複合での除外確認）
- [ ] **Phase 1 検証 & コミット**
  - [ ] ビルド & 単体テストの実行 (`go test ./internal/db/...`)
  - [ ] Git コミット

---

### 🔹 Phase 2: スキャナー & 低負荷ネットワーク検出エンジン
- [ ] **2.1 ネットワークスキャナー (`internal/scanner`)**
  - [ ] ICMP Ping による並列数制限付き IP スキャン（非特権データグラムソケット優先、OS別実装: Linux/macOSは`golang.org/x/net/icmp`の`udp4`/`udp6`、Windowsは`IcmpSendEcho`。送信失敗時は生ソケットへフォールバックせず対処法をログ表示）(仕様 2.5)
  - [ ] ホスト名・ネットワーク情報収集 (mDNS, NBNS, UPnP/SSDP)
  - [ ] OUIデータ (`internal/scanner/data/oui.csv`) の取得・同梱 & `go:embed` によるベンダー名解決ロジック (`oui.go`) (仕様 2.4)
  - [ ] ICMP TTL からの OS 推定ロジック
  - [ ] 新規端末 / 未承認端末検出判定 & `hosts` DB 登録（MACアドレス不一致時の別端末判定を含む、仕様 4.2.1）
  - [ ] セグメント未割当ホストの「未分類」セグメントへの自動割当
- [ ] **Phase 2 検証 & コミット**
  - [ ] ビルド & スキャナー単体テスト実行
  - [ ] Git コミット

---

### 🔹 Phase 3: Webhook 通知エンジン
- [ ] **3.1 Webhook 通知モジュール (`internal/notifier`)**
  - [ ] Webhook ペイロード生成処理 (`webhook.go`)
  - [ ] Slack / Discord / Teams / LINE 形式へのフォーマット変換（各プラットフォームのペイロード形式に沿ったテスト含む）
  - [ ] 未承認端末検出時の非同期 Webhook 即時送信処理
  - [ ] 通知の重複防止・再送ポリシー実装（初回検出のみ即時通知、down→up復帰時のみ再送、既存未承認の連続検出では再送しない）(仕様 8.1)
  - [ ] 大量新規端末同時検出時のバッチ通知（フラッド対策）(仕様 8.1)
  - [ ] Webhook送信失敗時のリトライ/タイムアウト処理
  - [ ] 未設定のWebhook URLに対する送信スキップ処理
- [ ] **Phase 3 検証 & コミット**
  - [ ] ビルド & Webhook 通知テスト実行
  - [ ] Git コミット

---

### 🔹 Phase 4: Uptime Kuma Socket.IO 双方向連携
- [ ] **4.1 Socket.IO クライアント & 同期処理 (`internal/kuma`)**
  - [ ] `breml/go-uptime-kuma-client` を用いた Uptime Kuma Socket.IO 接続処理 (`client.go`)
  - [ ] 認証未設定/認証設定あり（ユーザー名・パスワードによる`login`イベント）両モードへの対応、認証失敗時のエラー状態表示 (仕様 9.3)
  - [ ] 切断時の指数バックオフによる再接続処理 (仕様 9.2)
  - [ ] モニター情報の取得・自動インポート・照合ロジック (`sync.go`)
  - [ ] 照合パターン（パターン A: 一致、パターン B: 表示名競合 ⚠️、パターン C: 新規インポート、パターン D: Kuma側削除によるリンク解除）の実装 (仕様 9.1)
  - [ ] 起動時同期・定期同期（バックグラウンドタイマー）・手動同期（UIトリガー）の実装 (仕様 9.2)
  - [ ] Kuma アクション連動 (`addMonitor`, `pauseMonitor`, `resumeMonitor`, `editMonitor`, `deleteMonitor`)
- [ ] **Phase 4 検証 & コミット**
  - [ ] ビルド & モジュールテスト実行
  - [ ] Git コミット

---

### 🔹 Phase 5: Web UI & HTMX フロントエンド
- [ ] **5.1 テンプレート & 資材定義 (`web/`)**
  - [ ] `web/embed.go` によるテンプレート・静的ファイルの `go:embed`
  - [ ] 全体フレーム (`index.html`)
  - [ ] パーシャルテンプレート作成 (`sidebar.html`, `main_table.html`, `action_menu.html`, `conflict_modal.html`, `settings_modal.html`)
  - [ ] `settings_modal.html`: 保持日数選択、Webhook URL入力（Slack/Discord/Teams/LINE）、Uptime Kuma接続情報（URL / ユーザー名 / パスワード、いずれも未入力可＝認証未設定モード）入力欄 (仕様 9.3)
  - [ ] `main_table.html`: 承認状態列の「NEW」バッジ算出表示（`is_approved=0` かつ `first_seen` 24時間以内）(仕様 6.1)
  - [ ] ホスト手動追加フォーム（IP/セグメント/表示名入力、CIDR/IP形式バリデーション）(仕様 6.1)
  - [ ] セグメント追加フォームのCIDR形式・重複バリデーション表示 (仕様 4.1.1)
  - [ ] `conflict_modal.html`: 表示名競合時の「lanmap側を採用」/「Kuma側を採用」選択・同調アクション
- [ ] **5.2 HTTP ハンドラー & HTMX ルーティング (`internal/web`)**
  - [ ] HTTP ルーティング構築 (`router.go`)
  - [ ] メイン画面・セグメント切替・オンラインフィルタリングハンドラー (`handler.go`)
  - [ ] 三点リーダー (`...`) メニューアクションハンドラー (承認トグル, 削除保護トグル, メーカー/モデル手動編集, 表示名変更, Kuma監視開始/一時停止/削除)
  - [ ] ホスト手動追加・セグメント追加/編集/削除ハンドラー（`is_default`セグメント削除拒否含む）
- [ ] **Phase 5 検証 & コミット**
  - [ ] ビルド & UI/サーバー起動動作検証
  - [ ] Git コミット

---

### 🔹 Phase 6: CLI, サービス管理, メインエントリポイント & 総合検証
- [ ] **6.1 バックグラウンドサービス管理 (`internal/service`)**
  - [ ] OS共通インターフェース定義 (`service.go`)
  - [ ] `systemd` サービス定義自動生成 & インストール/アンインストール/起動/停止コマンド (`service_linux.go`) (仕様 2.5, 10)
  - [ ] `launchd` plist自動生成 & インストール/アンインストール/起動/停止コマンド (`service_darwin.go`) (仕様 2.5, 10)
  - [ ] `golang.org/x/sys/windows/svc` を用いたWindows Service登録・インストール/アンインストール/起動/停止コマンド (`service_windows.go`) (仕様 2.2, 10)
  - [ ] いずれのOSでも非特権ユーザーでの実行をデフォルトとする設定 (仕様 2.5)
- [ ] **6.2 TLS / HTTPS対応 (`internal/config`, `internal/web`)**
  - [ ] 自己署名証明書の自動生成処理（`crypto/tls`/`crypto/x509`、`<データディレクトリ>/certs/` への保存・再利用・有効期限切れ前の自動再生成）(仕様 2.6, 10.1)
  - [ ] `settings.tls_cert_path` / `tls_key_path` が指定された場合の `tls.LoadX509KeyPair` 読み込み・バリデーション（不正時は既存証明書へフォールバック）(仕様 10.1)
  - [ ] `ListenAndServeTLS` へのサーバー起動切り替え（デフォルトポート `https://localhost:3002`）
  - [ ] `settings_modal.html` へのTLS証明書パス入力欄追加 (仕様 10.1, Phase 5と連携)
- [ ] **6.3 エントリポイント & CLI (`cmd/lanmap/main.go`)**
  - [ ] CLI 引数解析 (通常起動 / `service` サブコマンド / `version`)
  - [ ] 定期スキャンタスク & クリーンアップタスクのバックグラウンド起動
  - [ ] 構造化ロギング実装（`INFO`/`WARN`/`ERROR`、`LANMAP_LOG_LEVEL` 環境変数対応）(仕様 10.2)
  - [ ] `SIGINT`/`SIGTERM` 受信時のグレースフルシャットダウン（スキャン/Kuma接続/HTTPサーバーの安全停止）(仕様 10.2)
- [ ] **6.4 Makefile & ドキュメント**
  - [ ] `Makefile` (ビルド・クロスコンパイル設定、Windows/macOS/Linux)
  - [ ] `README.md` 更新
- [ ] **Phase 6 最終検証 & コミット**
  - [ ] 全体ビルド & 総合テスト実行（Windows/macOS/Linux クロスコンパイル確認含む）
  - [ ] E2E統合シナリオ確認（スキャン検出→未承認DB登録→Webhook通知→UI表示→承認操作→Kuma監視開始の一連の流れ）
  - [ ] 最終 Git コミット
