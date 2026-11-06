# yamartx

[![Go Reference](
  <https://pkg.go.dev/badge/github.com/eggplants/yamartx.svg>
)](
  <https://pkg.go.dev/github.com/eggplants/yamartx>
) [![ci](
  <https://github.com/eggplants/yamartx/actions/workflows/ci.yml/badge.svg>
)](
  <https://github.com/eggplants/yamartx/actions/workflows/ci.yml>
) [![release](
  <https://github.com/eggplants/yamartx/actions/workflows/release.yml/badge.svg>
)](
  <https://github.com/eggplants/yamartx/actions/workflows/release.yml>
)

Yamaha RTX ルーターの設定コマンドを TOML 形式の設定ファイルで宣言的に管理する CLI です。

## Install

```sh
# via mise
mise use -g github:eggplants/yamartx

# via go
go install github.com/eggplants/yamartx/cmd/yamartx@latest
```

## Usage

```sh
# (初回) ルーターの設定を設定ファイルに書き出す
yamartx import -host 192.168.100.1 -user operator -o router.toml

# 差分を確認する
yamartx plan

# 確認のうえ反映して save する
yamartx apply

# 設定ファイルが表すコマンドを表示する
yamartx render

# ルーターの show config の内容をそのまま出力する (管理パスワードは不要)
yamartx show
```

`plan` の出力例:

```text
  + ip filter 400040 pass * 192.168.100.0/24 tcp * 443
  ~ [tunnel 1] ip tunnel mtu 1460
    => ip tunnel mtu 1400
  - dns static a grafana.home.arpa 192.168.100.4

Plan: 1 to add, 1 to change, 1 to remove. (4 protected lines ignored)
```

共通して `-c FILE` (既定値 `router.toml`) を指定できます。接続先は `-host` `-port` `-user` `-i` `-known-hosts` で上書きできます。

### 認証

ログインパスワードは `YAMARTX_PASSWORD`、管理パスワードは `YAMARTX_ADMIN_PASSWORD` で渡します。未設定なら端末で入力を求めます。公開鍵は `identity_file` (`-i`) か ssh-agent で使えます。

パスワード認証より、公開鍵認証によるSSH接続をおすすめします。

鍵が未交換の場合は、先に一度 `ssh` で接続して `import sshd authorized-keys [user]` で登録してください。

## 設定ファイル

全項目の例は [examples/router.toml](examples/router.toml) を参照してください。

```toml
[connection]
host = "192.168.100.1"
user = "operator"

[interface.lan1]
ip_address = "192.168.100.1/24"

[tunnel.1]
encapsulation = "map-e"
enable = true
ip_mtu = 1460
ip_nat_descriptor = "20000"

[tunnel.1.ip_secure_filter]
in = [400003, 400020]
out = [400013, 400099]
out_dynamic = [400098, 400099]

[ip.route]
default = "gateway tunnel 1"

[ip.filter]
400000 = { action = "reject", src = "10.0.0.0/8" }   # 省略した項目は *
400020 = { action = "reject", proto = "udp,tcp", src_port = "135" }

[dhcp.scope.1]
range = "192.168.100.2-192.168.100.191/24"
options = "dns=192.168.100.4,192.168.100.5"
binds = [
  { ip = "192.168.100.2", mac = "02:00:00:00:00:11" },
]

[dns]
host = "lan1"
static = [
  { type = "a", name = "nas.home.arpa", value = "192.168.100.17" },
]

# スキーマにないコマンドはそのまま書けます。[tunnel.N] と [pp.N] にも raw があります。
[raw]
commands = [
  "nat descriptor masquerade static 20000 1 192.168.100.4 tcp 443",
]
```

## 動作

- **TOML が正です。** ルーターにあって TOML にない設定は `no` で削除します。未知のキーはタイプミスとしてエラーにします。
- **秘密情報には触りません。** `login password`、`administrator password`、`login user`、`sshd host key generate` と、値が `*` でマスクされた行は比較も変更もしません。`login user foo *` を再投入するとパスワードが `*` に変わるためです。TOML に書くとエラーになります。
- **適用順に依存関係を反映します。** フィルタなどの定義を先に投入し、参照を更新してから、不要になったものを逆順で削除します。
- **失敗したら止まり、保存しません。** エラーで止まった場合や接続が切れた場合は `save` しないので、ルーターを再起動すれば元に戻せます。
- **適用後に検証します。** `show config` を読み直し、差分が残っていれば終了コード 1 で報告します。
- **締め出しを警告します。** `sshd`、LAN のアドレスやフィルタなど、接続を失うおそれのある変更は警告します。これらを含む場合、`-auto-approve` には `-allow-lockout-risk` が必要です。

`plan` もルーターに次の操作を行います。

- `show config` のために管理者モードに入ります。
- `console lines` と `console columns` を一時的に変更し、読み取り後に元へ戻します。この変更は `save` しません。

## 制限

- `show config` は既定値の設定を表示しません。既定値と同じ値を TOML に書くと差分が残ります (例: `telnetd service on`)。その行は TOML から消してください。
- ルーターが入力を別の形で表示すると差分が残ります (例: ポート番号と名前)。`apply` の検証で検出されるので、TOML を表示に合わせてください。
- `ip filter` / `ipv6 filter` の末尾の `*` は省略と同じものとして比較します。
- 文字コードが `ja.utf8` や `ascii` 以外のコンソールでは、`description` の日本語を正しく比較できません。
- `internal/rtx/line.go` の表にないコマンドは、削除時に `no <行全体>` を送ります。ルーターが受け付けなければ適用はそこで止まります。

## Development

```sh
mise trust
mise install

# モックサーバーでテスト
mise run ci
```

## License

MIT
