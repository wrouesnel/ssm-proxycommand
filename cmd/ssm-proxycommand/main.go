// Command ssm-proxycommand is an SSH ProxyCommand that carries the SSH connection over an AWS
// Systems Manager Session Manager session, selecting the instance and AWS profile from the
// hostname ssh was asked to connect to.
//
//	Host *.ssm
//	    ProxyCommand ssm-proxycommand --suffix=ssm %h %p
//
// lets `ssh ec2-user@web-server.prod.ssm` reach the running instance named "Web Server" using the
// "prod" AWS profile.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/alecthomas/kong"
)

var version = "dev"

// Globals are flags shared by every command. Each can also be set from the environment, which
// keeps ssh config ProxyCommand lines short.
type Globals struct {
	Suffix  []string `help:"Domain suffix to strip from hostnames before parsing, e.g. 'ssm' for web.prod.ssm. Repeatable." env:"SSM_PROXYCOMMAND_SUFFIX" sep:","`
	Profile string   `help:"Use this AWS profile for every host, instead of taking it from the hostname." env:"SSM_PROXYCOMMAND_PROFILE"`
	Region  string   `help:"AWS region, overriding the hostname and profile." env:"SSM_PROXYCOMMAND_REGION"`
	Styles  []string `help:"Instance selection styles to try, in order." default:"${styles}" env:"SSM_PROXYCOMMAND_STYLES" sep:","`
	TagKey  []string `help:"Tag keys matched by the 'tag' and 'slug' styles." default:"Name" env:"SSM_PROXYCOMMAND_TAG_KEYS" sep:","`
	Verbose int      `short:"v" type:"counter" help:"Log progress to stderr (or --log-file). Repeat for debug output."`
	LogFile string   `help:"Write logs to this file instead of stderr." type:"path" env:"SSM_PROXYCOMMAND_LOG_FILE"`
}

type CLI struct {
	Globals

	Proxy   ProxyCmd         `cmd:"" default:"withargs" help:"Connect stdin/stdout to a port on the instance (ProxyCommand mode). This is the default command."`
	Resolve ResolveCmd       `cmd:"" help:"Show which instance a hostname resolves to."`
	List    ListCmd          `cmd:"" help:"List the instances in a profile and the hostnames that select them."`
	Version kong.VersionFlag `help:"Print the version and exit."`
}

func main() {
	var cli CLI
	kctx := kong.Parse(&cli,
		kong.Name("ssm-proxycommand"),
		kong.Description("SSH ProxyCommand that tunnels SSH over AWS SSM Session Manager.\n\n"+
			"Hostnames take the form <instance>.<profile> or <instance>.<region>.<profile>, optionally "+
			"followed by a --suffix. <instance> may be an instance ID, private or public IP (10.0.0.1 "+
			"or ip-10-0-0-1), private or public DNS name, a tag value, or a slugified tag value "+
			"('Web Server' -> web-server) when exactly one running instance matches."),
		kong.UsageOnError(),
		kong.Vars{"version": version, "styles": defaultStyles()},
	)

	logger, closeLog, err := newLogger(cli.Globals)
	if err != nil {
		fatal(err)
	}
	defer closeLog()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()

	kctx.BindTo(ctx, (*context.Context)(nil))
	kctx.Bind(&cli.Globals, logger)
	if err := kctx.Run(); err != nil {
		if errors.Is(err, context.Canceled) {
			os.Exit(130)
		}
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "ssm-proxycommand: %v\n", err)
	os.Exit(1)
}

func newLogger(g Globals) (*slog.Logger, func(), error) {
	if g.Verbose == 0 && g.LogFile == "" {
		return slog.New(slog.DiscardHandler), func() {}, nil
	}
	level := slog.LevelInfo
	if g.Verbose > 1 {
		level = slog.LevelDebug
	}
	var w io.Writer = os.Stderr
	closer := func() {}
	if g.LogFile != "" {
		f, err := os.OpenFile(g.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, nil, err
		}
		w = f
		closer = func() { f.Close() }
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level})), closer, nil
}
