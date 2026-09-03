# lanmap 🛡️

**LAN Host Manager & Security Detector**

`lanmap` は、社内LANや拠点間VPNに接続されたネットワーク機器・端末を自動検出し、**持ち込みPCや未承認端末、野良ルーターなどの接続を早期警戒してネットワークセキュリティを守る**ための単一バイナリ型Webアプリケーションです。

スプレッドシート感覚の一覧画面で全端末を俯瞰・管理できるほか、新規端末の**即時アラート通知（Google Chat / Slack / Teams / Discord / LINE）**、**ブロードキャストストーム異常検知**、**詳細プロファイリング（Web管理画面名・型番・SSL証明書期限・オープンポート）**、および **内蔵の24時間/7日間 Ping 死活監視・稼働率集計エンジン** を標準搭載しています。

---

## 🌟 主な特長

1. **シングルバイナリ・外部依存なし（完全自己完結・CGO非依存）**
   * Docker や Node.js、追加の外部監視サーバーは一切不要。Go と `modernc.org/sqlite` によるピュアGo実装。Web UI資材、高精細ベクターFavicon、OUIデータベースもバイナリ内に完全内包。
2. **安全・低負荷な自動スキャン & マルチNIC安全設計**
   * 一般ユーザー権限で動作する非侵入型 ICMP Ping、mDNS、NetBIOS、UPnP/SSDP、OUIメーカー推定。
   * **マルチNIC・仮想NIC安全設計**: 複数NIC環境（業務LAN/検証用LAN/VPN/Docker等）では、OSのルーティング情報から **Default Gateway を持つメインNICのみをデフォルトでスキャン有効化**。その他のNICは安全のため停止状態で自動登録され、左カラムの「`...`」メニューからワンクリックでいつでもスキャン対象に追加・一時停止を切り替え可能。
3. **未承認端末の即時 Webhook 通知**
   * 社内管理下にない未知の端末を検出した際、**Google Chat**、**Slack**、**Microsoft Teams**、**Discord**、**LINE Notify** へ即座にアラート送信。
4. **資産管理台帳（ホワイトリスト）CSV/TSV 一括インポート**
   * 管理PCのホスト名・MACアドレス・シリアル番号一覧を取り込むことで、検出時に自動照合・承認し、未知端末のみをアラート対象化。
5. **ブロードキャストストーム & 異常トラフィック自動検知**
   * ループ配線や故障端末の暴走、マルウェアによるLAN内スキャンをリアルタイム監視し、画面ハイライト & Webhook警告。
6. **📈 24時間 Ping レスポンス時系列タイムライン & 稼働ヒートマップ**
   * 各ホスト行にインライン埋め込みされた時間比例 SVG タイムライン（30分刻み）により、回線の瞬断やLAN内遅延の変動、未計測区間（停止期間）を一目で把握。
7. **📊 ホスト行クリック詳細モーダル & ⚡ オンデマンド即時 Ping 診断**
   * テーブルの行をクリックするだけで、**過去7日間の詳細な遅延推移グラフ（SVG・日付目盛り付き）**、**時間帯別稼働ヒートマップ（4時間毎）**、**稼働率・平均/最小/最大RTT・ジッター統計**、およびその場で即時疎通チェックが打てる「⚡ 今すぐPing診断」を備えた詳細モーダルを表示。
8. **🔍 瞬時（0ms）リアルタイム・キーワード検索 & フィルタリング**
   * IP、ホスト名、表示名、メーカー、モデル、OS、ポート番号、接続形態（Wi-Fi/有線）、承認状態などの複合キーワードで即座にインクリメンタル絞り込み。
9. **🔌 有線LAN / 📶 Wi-Fi 接続形態の自動判定 & インフラ機器認識**
   * デバイスカテゴリ、ネットワーク機器ベンダー（AP/ルーター/スイッチ）、プライベートMAC（LAA）、通信レイテンシ/ジッター特性から、物理ケーブル接続か無線接続かを高精度に自動判定。
10. **ホスト詳細ホバーカード & 5大拡張プロファイリング**
    * IP/ホスト名/表示名にマウスを合わせるだけで、**Web管理画面名（`<title>`）**、**UPnP詳細型番・シリアル**、**TLS証明書期限（失効前警告）**、**mDNSモデル**、**オープンポート**、**Ping応答速度 & ジッター** を瞬時に確認。画面端での自動反転にも対応。
11. **厳格なエビデンスベースの OS / 機種特定エンジン**
    * 曖昧なホスト名文字列からの推測を排除し、mDNS ポート 5353 署名、SSH バナー、Web 管理画面ヘッダーなどの客観的エビデンスに基づく高精度なモデル・OS 判定。
12. **🔔 設定画面での Webhook 即時テスト送信機能**
    * Google Chat / Slack / Teams / Discord の各 Webhook URL に対してワンクリックで疎通テスト通知を即時送信可能。
13. **🚀 ワンクリック＆コマンド一発の自動セルフアップデート (GitHub Releases 連携)**
    * Web UI の設定モーダルから「今すぐアップデートして再起動」、または CLI で `lanmap update` を実行するだけで、GitHub Releases から最新バイナリを自動取得し、安全にインプレース置換＆自動再起動。
14. **OSサービス対応 & 常時 HTTPS**
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

# 最新バージョンへの自動セルフアップデート (GitHub Releasesから自動取得・置換)
./lanmap update      # または ./lanmap upgrade

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
