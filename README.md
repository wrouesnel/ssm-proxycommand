# ssm-proxycommand

An SSH `ProxyCommand` that carries your SSH connection over an
[AWS Systems Manager Session Manager](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html)
session. It picks the EC2 instance **and** the AWS profile from the hostname you type:

```console
$ ssh ec2-user@web-server.prod.ssm          # running instance whose Name is "Web Server", profile "prod"
$ ssh ec2-user@i-0123456789abcdef0.dev.ssm  # by instance ID, profile "dev"
$ ssh ec2-user@10.1.2.3.us-west-2.prod.ssm  # by private IP, in another region
```

You don't need inbound security group rules, bastion hosts, public IPs, the AWS CLI, or
`session-manager-plugin`. The Session Manager data channel protocol is implemented natively in Go,
including:

- reliable, ordered delivery (sequence numbers, acknowledgements, adaptive retransmission);
- flow control (the agent's pause/start publication messages, plus a bounded send window);
- **transparent reconnection**: if the websocket drops, the session is resumed with
  `ssm:ResumeSession` and unacknowledged data is resent, so the SSH connection survives;
- KMS session encryption, when your Session Manager preferences require it;
- SigV4-signed data channel connections.

## Install

Download an archive for your platform from the
[releases page](https://github.com/wrouesnel/ssm-proxycommand/releases) (Linux, macOS, Windows
and FreeBSD; `SHA256SUMS` lists the checksums), and put `ssm-proxycommand` on your `PATH`.

Or build it with Go:

```sh
go install github.com/wrouesnel/ssm-proxycommand/cmd/ssm-proxycommand@latest
```

## Configure ssh

Add this to `~/.ssh/config`:

```ssh-config
Host *.ssm
    ProxyCommand ssm-proxycommand --suffix=ssm %h %p
    # Optional: keep known_hosts entries stable however you name the instance.
    # HostKeyAlias %h
```

The `--suffix` is stripped before the hostname is parsed. It lets a `Host` pattern route only these
hosts through SSM. You can use any suffix, or none if you'd rather match hosts another way.

> ssh matches `Host` patterns case-sensitively against the name you type. Use a lower-case suffix
> (`web.prod.ssm`, not `web.prod.SSM`). Everything before the suffix is case-insensitive.

## Hostname format

```text
<instance>.<profile>[.<suffix>]
<instance>.<region>.<profile>[.<suffix>]
```

- **`<profile>`** is a profile from `~/.aws/config` or `~/.aws/credentials`, matched
  case-insensitively, because ssh lowercases hostnames. Profile names that contain dots work: the
  longest known profile that ends the hostname wins. `default` is always accepted. Pass `--profile`
  to use a fixed profile and leave it out of the hostname.
- **`<region>`** is optional and overrides the profile's region (`--region` overrides both).
- **`<instance>`** may contain dots. It is resolved using the styles below.

### Instance selection styles

The styles are tried in this order. The first style that matches *any* instance decides the
result.

| Style         | Example `<instance>`                         | Matches |
|---------------|----------------------------------------------|---------|
| `id`          | `i-0123456789abcdef0`, `mi-0123…`            | Instance or managed node ID. Used directly, without an EC2 lookup. |
| `private-ip`  | `10.0.1.5`, `ip-10-0-1-5`                    | A private IPv4 address on any of the instance's network interfaces. |
| `public-ip`   | `203.0.113.7`, `ip-203-0-113-7`              | The instance's public IPv4 address. |
| `private-dns` | `ip-10-0-1-5.ec2.internal`                   | The private DNS name. |
| `public-dns`  | `ec2-203-0-113-7.compute-1.amazonaws.com`    | The public DNS name. |
| `tag`         | `bastion`                                    | A tag value (default tag `Name`), compared case-insensitively. |
| `slug`        | `web-server-blue` for `Name=Web Server (Blue)` | The slugified tag value: lowercased, with each run of characters other than `a-z0-9` replaced by `-`. |

Rules:

- Only **running** instances are selected. If only stopped or pending instances match, you get an
  error that lists them.
- If **more than one** running instance matches in the deciding style, the connection is refused
  and the candidates are listed with their instance IDs. No instance is chosen arbitrarily. An exact
  `tag` match is tried before `slug`, so `web_server` still selects the instance with that exact name
  when `web-server` would be ambiguous.
- Use `--styles` to limit or reorder the styles (for example `--styles=id,slug`), and `--tag-key`
  to match other tags (for example `--tag-key=Name,Hostname`).

## Commands

```console
$ ssm-proxycommand --suffix=ssm list prod
INSTANCE             STATE    NAME         PRIVATE IP  PUBLIC IP    HOSTNAME
i-0a1b2c3d4e5f60718  running  Web Server   10.0.0.2    203.0.113.2  web-server.prod.ssm
i-0a1b2c3d4e5f60719  running  dupe         10.0.0.3    -            i-0a1b2c3d4e5f60719.prod.ssm
i-0a1b2c3d4e5f6071a  running  Dupe         10.0.0.4    -            i-0a1b2c3d4e5f6071a.prod.ssm

$ ssm-proxycommand --suffix=ssm resolve web-server.prod.ssm
i-0a1b2c3d4e5f60718	profile=prod region=ap-southeast-2 style=slug
  i-0a1b2c3d4e5f60718  running  Name="Web Server"  10.0.0.2
```

`proxy <host> [port]` is the default command. It's what `ProxyCommand` runs.

## Options

Every flag can also be set with an environment variable: upper-case it, replace `-` with `_` and
add the prefix `SSM_PROXYCOMMAND_`. For example, `--tag-key` becomes `SSM_PROXYCOMMAND_TAG_KEY`.

| Flag | Default | |
|------|---------|-|
| `--suffix` | | Suffixes to strip, comma separated. |
| `--profile` | | Use one profile for every host. |
| `--region` | | Override the region. |
| `--styles` | all, in table order | Selection styles to try. |
| `--tag-key` | `Name` | Tags used by `tag` and `slug`. |
| `--document` | `AWS-StartSSHSession` | Port-forwarding SSM document to start. |
| `--reason` | | Session reason, recorded in CloudTrail. |
| `--plugin` | off | Hand the session to `session-manager-plugin` instead of the built-in client. |
| `--log-level` | `warn` | Log level (`debug`, `info`, `warn`, `error`). |
| `--log-output-paths` | `stderr` | Where logs go. ssh shows stderr in your terminal, so use a file for `debug`. |
| `--log-format` | `console` | `console` or `json`. |

There's no configuration file, because ssh runs the ProxyCommand from whatever directory you're in.
Use flags in the `ProxyCommand` line, or the environment variables.

## Credentials and permissions

Credentials come from the standard AWS SDK chain for the selected profile. That includes SSO,
`credential_process`, and role assumption. Some practical points:

- When a role assumption needs an MFA code, you're prompted on the terminal (`/dev/tty`), because
  stdin and stdout carry the SSH stream.
- When an SSO session has expired, the error suggests running `aws sso login --profile <profile>`.

The IAM principal needs these permissions:

- `ec2:DescribeInstances`. Not needed when you only connect by instance ID.
- `ssm:StartSession` on the instance and on the `AWS-StartSSHSession` document.
- `ssm:ResumeSession` and `ssm:TerminateSession` on its own sessions.
- `kms:GenerateDataKey` on the session key, if Session Manager KMS encryption is enabled.

The instance must be a managed node with the SSM agent online, and it must be running `sshd`. Your
SSH key still has to be authorised on the instance. This tool only replaces the network path.

## How it works

1. The hostname is parsed into a selector, a profile and an optional region. The selector is then
   resolved to one running instance through `ec2:DescribeInstances`.
2. `ssm:StartSession` starts the `AWS-StartSSHSession` document with `portNumber=%p`.
3. The returned stream URL is opened as a websocket and the session token is presented. The agent's
   handshake is answered, and KMS encryption keys are negotiated if the agent requests them.
4. stdin and stdout are bridged to the session's byte stream until ssh closes the connection or the
   remote port closes. The session is then ended with the agent's terminate flag and
   `ssm:TerminateSession`.

## Development

The project follows [golang-template](https://github.com/wrouesnel/golang-template) and builds
with [mage](https://magefile.org). Run every command from the repository root:

```sh
go run mage.go binary      # build into bin/ and symlink ./ssm-proxycommand
go run mage.go test        # run the tests
go run mage.go lint        # golangci-lint
go run mage.go style       # check formatting (go run mage.go fmt fixes it)
go run mage.go releaseAll  # cross-compile release archives into release/
```

| Path | Purpose |
|---|---|
| `cmd/ssm-proxycommand/` | Minimal `main`. It only calls the entrypoint. |
| `pkg/entrypoints/ssm_proxycommand/` | Command line, logging and the `proxy`, `resolve` and `list` commands. |
| `pkg/hostspec/` | Parses hostnames into a selector, profile and region. |
| `pkg/selector/` | Resolves a selector to an EC2 instance. |
| `pkg/ssmsession/` | The Session Manager data channel client. |
| `pkg/ssmproto/` | The data channel wire format, handshake payloads and encryption. |
| `internal/fakeaws/` | Test doubles: a fault-injecting SSM agent, fake EC2/SSM APIs and an SSH server. |

The tests include:

- a fake SSM agent with fault injection (dropped, duplicated and reordered messages, and websocket
  disconnects);
- KMS encryption tests;
- an SSH handshake over a lossy session;
- end-to-end tests that run the system `ssh` client with this binary as its `ProxyCommand`, against
  fake EC2 and SSM endpoints (`AWS_ENDPOINT_URL`).

## Releases

Pushing a `v*` tag runs `.github/workflows/release.yml`. It runs the full CI, cross-compiles
archives for every platform, and publishes them with `SHA256SUMS` as a GitHub release.
