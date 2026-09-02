# lanmap (lmap) 🛡️

**LAN Host Manager & Security Detector**

`lanmap`（CLIエイリアス: `lmap`）は、LANおよび拠点間VPN/リモートアクセスVPN等に接続されたネットワーク機器・ホストを自動検出し、**社内LANへの不正端末・未承認端末（持ち込みPC、野良ルーター、シャドーIT等）の接続を早期発見・警戒してネットワークセキュリティを守る**ための単一バイナリ型Webアプリケーションです。

---

## 🌟 主な特長

1. **シングルバイナリ・外部依存なし (CGO非依存)**
   * Go 1.22+ と `modernc.org/sqlite` によるピュアGo実装。フロントエンド資材・OUIデータベースもバイナリ内に内包。
2. **低負荷・非侵入型ネットワークスキャン**
   * 一般ユーザー権限で動作する非特権ICMP Ping、mDNS、NetBIOS (NBNS)、OUIメーカー推定。ポートスキャンや攻撃的パケットは行いません。
3. **未承認端末の即時 Webhook 通知**
   * 未登録・未承認の端末が検出された際、Slack / Discord / Microsoft Teams / LINE Notify へ即時アラート送信（重複防止・バッチ送信機能付き）。
4. **Uptime Kuma 双方向連携 (Socket.IO)**
   * Uptime Kuma の監視対象と自動同期・インポート・表示名競合検知・Web UIからのワンクリック監視開始/停止。
5. **スプレッドシート感覚のモダンWeb UI**
   * HTMX + Tailwind CSSによる高速なSSR UI。直感的な `...` アクションメニューから承認/削除保護/監視切り替え。
6. **OSサービス対応**
   * Linux (`systemd`), macOS (`launchd`), Windows Service (`golang.org/x/sys/windows/svc`) への登録・管理コマンド内蔵。
7. **常時 HTTPS / TLS暗号化**
   * 初回起動時に自己署名証明書を自動生成、カスタム証明書（Let's Encrypt等）の指定も可能。

---

## 🚀 クイックスタート

### 1. ビルド
```bash
# バイナリ (lmap) のビルド
make build

# 全OS向けクロスコンパイル (Linux / macOS / Windows)
make cross-compile
```

### 2. 起動
```bash
./lmap
```
起動後、ブラウザで **`https://localhost:3002`** を開きます（自己署名証明書の警告が表示された場合は続行してください）。

---

## 🛠️ コマンド & サービス管理

```bash
# 通常起動 (フォアグラウンド)
./lmap

# バージョン表示
./lmap version

# バックグラウンドサービス管理 (Linux: systemd / macOS: launchd / Windows: SCM)
./lmap service install    # サービス登録
./lmap service start      # サービス起動
./lmap service status     # サービス稼働状態確認
./lmap service stop       # サービス停止
./lmap service restart    # サービス再起動
./lmap service uninstall  # サービス削除
```

---

## ⚙️ 環境変数設定

| 環境変数名 | 説明 | デフォルト値 |
|---|---|---|
| `LANMAP_DATA_DIR` | DBファイル・TLS証明書の保存先ディレクトリ | 実行ファイルと同階層 |
| `LANMAP_PORT` | HTTPS待受ポート | `3002` |
| `LANMAP_SCAN_INTERVAL_MINUTES` | 定期スキャン間隔（分） | `10` |
| `LANMAP_SCAN_CONCURRENCY` | Ping並列送信数制限 | `20` |
| `LANMAP_LOG_LEVEL` | ログ出力レベル (`DEBUG` / `INFO` / `WARN` / `ERROR`) | `INFO` |

---

## 📋 テスト実行

```bash
make test
# または
go test -v ./...
```

---

## 📄 ライセンス
MIT License
