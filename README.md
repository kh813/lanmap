# lanmap 🛡️

**LAN Host Manager & Security Detector**

`lanmap` は、社内LANや拠点間VPNに接続されたネットワーク機器・端末を自動検出し、**持ち込みPCや未承認端末、野良ルーターなどの接続を早期警戒してネットワークセキュリティを守る**ための単一バイナリ型Webアプリケーションです。

スプレッドシート感覚の一覧画面で全端末を俯瞰・管理できるほか、新規端末の**即時アラート通知（Google Chat / Slack / Teams / Discord / LINE）**、**ブロードキャストストーム異常検知**、**詳細プロファイリング（Web管理画面名・型番・SSL証明書期限・オープンポート）**、および **Uptime Kuma** との Socket.IO 双方向連携をサポートしています。

---

## 🌟 主な特長

1. **シングルバイナリ・外部依存なし（CGO非依存）**
   * Go 1.22+ と `modernc.org/sqlite` によるピュアGo実装。Web UI資材やOUIデータベースもバイナリ内に完全内包。
2. **安全・低負荷な自動スキャン**
   * 一般ユーザー権限で動作する非侵入型 ICMP Ping、mDNS、NetBIOS、UPnP/SSDP、OUIメーカー推定。
3. **未承認端末の即時 Webhook 通知**
   * 社内管理下にない未知の端末を検出した際、**Google Chat**、**Slack**、**Microsoft Teams**、**Discord**、**LINE Notify** へ即座にアラート送信。
4. **資産管理台帳（ホワイトリスト）CSV/TSV 一括インポート**
   * 管理PCのホスト名・MACアドレス・シリアル番号一覧を取り込むことで、検出時に自動照合・承認し、未知端末のみをアラート対象化。
5. **ブロードキャストストーム & 異常トラフィック自動検知**
   * ループ配線や故障端末の暴走、マルウェアによるLAN内スキャンをリアルタイム監視し、画面ハイライト & Webhook警告。
6. **7日間 Ping レスポンス時系列推移 & Uptime Kuma スタイル稼働ブロック**
   * 直近7日間の遅延推移（SVG スパークライン）と稼働率・死活ブロックを内蔵し、回線の瞬断や不安定さを一目で把握。
7. **🔌 有線LAN / 📶 Wi-Fi 接続形態の自動判別**
   * デバイスカテゴリ、プライベートMAC（LAA）、通信レイテンシ/ジッター特性から、物理ケーブル接続か無線接続かを高精度に自動判定。未承認端末の物理接続箇所の特定を強力にアシスト。
8. **ホスト詳細ホバーカード & 5大拡張プロファイリング**
   * IP/ホスト名/表示名にマウスを合わせるだけで、**Web管理画面名（`<title>`）**、**UPnP詳細型番・シリアル**、**TLS証明書期限（失効前警告）**、**mDNSモデル**、**オープンポート**、**Ping応答速度 & ジッター** を瞬時に確認。画面端での自動反転にも対応。
9. **Uptime Kuma 双方向連携 (Socket.IO)**
   * Uptime Kuma の監視対象と自動同期・インポート・表示名競合検知・Web UIからのワンクリック監視開始/停止。
10. **OSサービス対応 & 常時 HTTPS**
    * Linux (`systemd`), macOS (`launchd`), Windows Service への常駐登録コマンドを内蔵。初回起動時に自己署名TLS証明書を自動生成。

---

## 🚀 クイックスタートガイド

### 1. ダウンロード & インストール

[GitHub Releases](https://github.com/kh813/lanmap/releases/latest) からお使いのOS向けのZIPアーカイブをダウンロードして展開します。

* **macOS (Apple Silicon)**: `lanmap-mac-arm64.zip`
* **Linux (x64)**: `lanmap-linux-x64.zip`
* **Linux (arm64)**: `lanmap-linux-arm64.zip`
* **Windows (x64)**: `lanmap-win-x64.zip`
* **Windows (arm64)**: `lanmap-win-arm64.zip`

展開すると、即実行可能な **`lanmap`**（Windowsは `lanmap.exe`）が取り出せます。

```bash
# 例: macOS / Linux の場合
unzip lanmap-mac-arm64.zip
chmod +x lanmap
./lanmap
```

### 2. ブラウザでアクセス

ブラウザで **`https://localhost:3002`** を開きます。  
（※初回は自己署名証明書の警告が表示されますが、そのまま「アクセスを続行」してください）

### 3. 初期設定（3分で完了）

1. **画面左下の「⚙️ 設定画面」をクリック**:
   - Google Chat や Slack、Teams の Webhook URL を登録すると、未承認端末の検出時に即時通知されます。
   - 古い端末の自動クリーンアップ期間（デフォルト: 90日）も設定できます。
2. **サイドバーの「📋 台帳ホワイトリスト登録」をクリック**:
   - お手元のPC管理台帳（CSV/TSV）を貼り付けるかドラッグ＆ドロップすると、既存端末が一括で「🟢 承認済み」になります。
3. **右上の「⚡ Scan Now」をクリック**:
   - 手動でLAN内を即座にフルスキャンし、すべての端末を自動検出します。

---

## 🛠️ コマンド & 常駐サービス化

`lanmap` には、OS標準のバックグラウンドサービスとして常駐させるコマンドが内蔵されています。

```bash
# 通常起動 (フォアグラウンド実行)
./lanmap

# バージョン確認
./lanmap version

# サービス管理 (Linux: systemd / macOS: launchd / Windows: SCM)
./lanmap service install    # バックグラウンドサービスに登録
./lanmap service start      # サービス開始
./lanmap service status     # 稼働状態確認
./lanmap service stop       # サービス停止
./lanmap service restart    # サービス再起動
./lanmap service uninstall  # サービス削除
```

---

## ⚙️ 環境変数設定 (オプション)

| 環境変数名 | 説明 | デフォルト値 |
|---|---|---|
| `LANMAP_DATA_DIR` | DBファイル・TLS証明書の保存先ディレクトリ | 実行ファイルと同階層 |
| `LANMAP_PORT` | HTTPS待受ポート | `3002` |
| `LANMAP_SCAN_INTERVAL_MINUTES` | 定期スキャン間隔（分） | `2` |
| `LANMAP_SCAN_CONCURRENCY` | Ping並列送信数制限 | `20` |
| `LANMAP_LOG_LEVEL` | ログ出力レベル (`DEBUG` / `INFO` / `WARN` / `ERROR`) | `INFO` |

---

## 🏗️ ソースコードからのビルド

Go 1.22 以上がインストールされている環境で以下を実行します：

```bash
# ローカル用バイナリのビルド
make build

# 全OS向けZIPパッケージの一括生成
make cross-compile

# 単体テストの実行
make test
```

---

## 📄 ライセンス

MIT License
