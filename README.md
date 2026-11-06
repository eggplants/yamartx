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

A CLI for declaratively managing the configuration commands of Yamaha RTX routers with a TOML configuration file.

## Install

```sh
# via mise
mise use -g github:eggplants/yamartx

# via go
go install github.com/eggplants/yamartx/cmd/yamartx@latest
```

## Usage

```sh
# (First time) Export the router's configuration to a configuration file
yamartx import -host 192.168.100.1 -user operator -o router.toml

# Review the differences
yamartx plan

# Confirm, apply the changes, and save
yamartx apply

# Print the commands the configuration file describes
yamartx render

# Print the router's show config output as is (needs no administrator password)
yamartx show
```

Example `plan` output:

```text
  + ip filter 400040 pass * 192.168.100.0/24 tcp * 443
  ~ [tunnel 1] ip tunnel mtu 1460
    => ip tunnel mtu 1400
  - dns static a grafana.home.arpa 192.168.100.4

Plan: 1 to add, 1 to change, 1 to remove. (4 protected lines ignored)
```

All of these commands accept `-c FILE` (default: `router.toml`). The connection target can be overridden with `-host`, `-port`, `-user`, `-i`, and `-known-hosts`.

### Authentication

Pass the login password in `YAMARTX_PASSWORD` and the administrator password in `YAMARTX_ADMIN_PASSWORD`. If they are unset, you are prompted for them in the terminal. Public keys can be used through `identity_file` (`-i`) or ssh-agent.

Public key authentication is recommended over password authentication for SSH connections.

If you have not exchanged keys yet, connect once with `ssh` first and register your key with `import sshd authorized-keys [user]`.

## Configuration file

See [examples/router.toml](examples/router.toml) for an example of all the items.

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
400000 = { action = "reject", src = "10.0.0.0/8" }   # Omitted fields mean *
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

# Commands not covered by the schema can be written as is. [tunnel.N] and [pp.N] also have raw.
[raw]
commands = [
  "nat descriptor masquerade static 20000 1 192.168.100.4 tcp 443",
]
```

## Behavior

- **The TOML file is the source of truth.** Settings that exist on the router but not in the TOML file are removed with `no`. Unknown keys are treated as typos and cause an error.
- **Secrets are left alone.** `login password`, `administrator password`, `login user`, `sshd host key generate`, and lines whose values are masked with `*` are neither compared nor changed, because re-sending `login user foo *` would change the password to `*`. Writing them in the TOML file is an error.
- **The apply order follows dependencies.** Definitions such as filters are sent first, references are updated next, and anything no longer needed is then removed in reverse order.
- **On failure, it stops without saving.** If it stops on an error or the connection drops, `save` is not run, so restarting the router restores the previous configuration.
- **Results are verified after applying.** `show config` is read again, and any remaining differences are reported with exit code 1.
- **Lockout risks are flagged.** Changes that could cut off your connection, such as `sshd` settings or LAN addresses and filters, trigger a warning. When a plan contains them, `-auto-approve` also requires `-allow-lockout-risk`.

`plan` also performs the following operations on the router:

- It enters administrator mode to run `show config`.
- It temporarily changes `console lines` and `console columns`, and restores them after reading. These changes are not saved.

## Limitations

- `show config` does not display settings at their default values. Writing a default value in the TOML file leaves a permanent difference (e.g. `telnetd service on`). Remove that line from the TOML file.
- Differences also remain when the router displays input in another form (e.g. port numbers and names). The verification in `apply` detects this, so make the TOML file match what the router displays.
- Trailing `*` fields in `ip filter` / `ipv6 filter` are compared as if they were omitted.
- On consoles with a character encoding other than `ja.utf8` or `ascii`, Japanese text in `description` cannot be compared correctly.
- For commands not in the table in `internal/rtx/line.go`, removal sends `no <entire line>`. If the router rejects it, the apply stops there.

## Development

```sh
mise trust
mise install

# Run the tests against the mock server
mise run ci
```

## License

MIT
