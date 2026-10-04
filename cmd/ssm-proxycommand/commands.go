package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/ssm"

	"github.com/wrouesnel/ssm-proxycommand/pkg/hostspec"
	"github.com/wrouesnel/ssm-proxycommand/pkg/selector"
	"github.com/wrouesnel/ssm-proxycommand/pkg/ssmsession"
)

func defaultStyles() string {
	s := make([]string, len(selector.AllStyles))
	for i, st := range selector.AllStyles {
		s[i] = string(st)
	}
	return strings.Join(s, ",")
}

// target is a hostname resolved to an AWS configuration and instance.
type target struct {
	spec  hostspec.Spec
	cfg   aws.Config
	match *selector.Match
}

func parseHost(g *Globals, host string) (hostspec.Spec, error) {
	opts := hostspec.Options{Suffixes: g.Suffix, Profile: g.Profile, Region: g.Region}
	if g.Profile == "" {
		profiles, err := hostspec.KnownProfiles()
		if err != nil {
			return hostspec.Spec{}, fmt.Errorf("reading AWS profiles: %w", err)
		}
		opts.Profiles = profiles
	}
	return hostspec.Parse(host, opts)
}

// loadAWSConfig loads the SDK configuration for a profile. Stdin and stdout belong to ssh, so an
// MFA prompt for role assumption goes to the controlling terminal instead.
func loadAWSConfig(ctx context.Context, profile, region string) (aws.Config, error) {
	opts := []func(*config.LoadOptions) error{
		config.WithAssumeRoleCredentialOptions(func(o *stscreds.AssumeRoleOptions) {
			o.TokenProvider = ttyTokenProvider
		}),
	}
	if profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}
	if region != "" {
		opts = append(opts, config.WithRegion(region))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("loading AWS profile %q: %w", profile, err)
	}
	if cfg.Region == "" {
		return aws.Config{}, fmt.Errorf("no region for profile %q: set one in the profile, use <instance>.<region>.<profile>, or pass --region", profile)
	}
	return cfg, nil
}

func ttyTokenProvider() (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", fmt.Errorf("MFA token required but no terminal is available: %w", err)
	}
	defer tty.Close()
	fmt.Fprint(tty, "Enter MFA code: ")
	line, err := bufio.NewReader(tty).ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func resolveTarget(ctx context.Context, g *Globals, log *slog.Logger, host string) (*target, error) {
	spec, err := parseHost(g, host)
	if err != nil {
		return nil, err
	}
	log.Debug("parsed hostname", "selector", spec.Selector, "profile", spec.Profile, "region", spec.Region)
	cfg, err := loadAWSConfig(ctx, spec.Profile, spec.Region)
	if err != nil {
		return nil, err
	}
	r, err := newResolver(g, cfg)
	if err != nil {
		return nil, err
	}
	m, err := r.Resolve(ctx, spec.Selector)
	if err != nil {
		return nil, withCredentialHint(err, spec.Profile)
	}
	log.Info("resolved instance", "instance", m.InstanceID, "style", m.Style, "profile", spec.Profile, "region", cfg.Region)
	return &target{spec: spec, cfg: cfg, match: m}, nil
}

func newResolver(g *Globals, cfg aws.Config) (*selector.Resolver, error) {
	styles, err := selector.ParseStyles(g.Styles)
	if err != nil {
		return nil, err
	}
	return &selector.Resolver{EC2: ec2.NewFromConfig(cfg), Styles: styles, TagKeys: g.TagKey}, nil
}

// withCredentialHint adds a remedy to errors that usually mean an expired SSO login.
func withCredentialHint(err error, profile string) error {
	if selector.IsResolutionError(err) {
		return err
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "sso") || strings.Contains(msg, "token") && strings.Contains(msg, "expired") {
		return fmt.Errorf("%w\n(try: aws sso login --profile %s)", err, profile)
	}
	return err
}

// ProxyCmd is the ProxyCommand entry point.
type ProxyCmd struct {
	Host     string `arg:"" help:"Hostname from ssh (%h)."`
	Port     int    `arg:"" optional:"" default:"22" help:"Port on the instance (%p)."`
	Document string `help:"SSM document that starts the port session." default:"AWS-StartSSHSession" env:"SSM_PROXYCOMMAND_DOCUMENT"`
	Reason   string `help:"Reason recorded against the session in CloudTrail."`
	Plugin   bool   `help:"Use the session-manager-plugin binary for the data channel instead of the built-in client." env:"SSM_PROXYCOMMAND_USE_PLUGIN"`
}

func (c *ProxyCmd) Run(ctx context.Context, g *Globals, log *slog.Logger) error {
	t, err := resolveTarget(ctx, g, log, c.Host)
	if err != nil {
		return err
	}
	ssmClient := ssm.NewFromConfig(t.cfg)
	in := &ssm.StartSessionInput{
		Target:       aws.String(t.match.InstanceID),
		DocumentName: aws.String(c.Document),
		Parameters:   map[string][]string{"portNumber": {strconv.Itoa(c.Port)}},
	}
	if c.Reason != "" {
		in.Reason = aws.String(c.Reason)
	}
	out, err := ssmClient.StartSession(ctx, in)
	if err != nil {
		return withCredentialHint(fmt.Errorf("starting SSM session to %s: %w", t.match.InstanceID, err), t.spec.Profile)
	}
	sessionID := aws.ToString(out.SessionId)
	log.Info("session started", "session", sessionID)
	defer terminateSession(ssmClient, sessionID, log)

	if c.Plugin {
		return runPlugin(ctx, t, in, out)
	}
	return ssmsession.Run(ctx, ssmsession.Options{
		SessionID:   sessionID,
		StreamURL:   aws.ToString(out.StreamUrl),
		TokenValue:  aws.ToString(out.TokenValue),
		TargetID:    t.match.InstanceID,
		Region:      t.cfg.Region,
		Credentials: t.cfg.Credentials,
		KMS:         kms.NewFromConfig(t.cfg),
		Resume: func(ctx context.Context) (string, string, error) {
			r, err := ssmClient.ResumeSession(ctx, &ssm.ResumeSessionInput{SessionId: out.SessionId})
			if err != nil {
				return "", "", err
			}
			return aws.ToString(r.TokenValue), aws.ToString(r.StreamUrl), nil
		},
		Logger: log,
		Stderr: os.Stderr,
	}, os.Stdin, os.Stdout)
}

func terminateSession(client *ssm.Client, sessionID string, log *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := client.TerminateSession(ctx, &ssm.TerminateSessionInput{SessionId: aws.String(sessionID)}); err != nil {
		log.Debug("terminating session", "session", sessionID, "error", err)
	}
}

// runPlugin hands the session to session-manager-plugin, the way the AWS CLI does.
func runPlugin(ctx context.Context, t *target, in *ssm.StartSessionInput, out *ssm.StartSessionOutput) error {
	resp, _ := json.Marshal(map[string]string{
		"SessionId":  aws.ToString(out.SessionId),
		"StreamUrl":  aws.ToString(out.StreamUrl),
		"TokenValue": aws.ToString(out.TokenValue),
	})
	req, _ := json.Marshal(map[string]any{
		"Target":       aws.ToString(in.Target),
		"DocumentName": aws.ToString(in.DocumentName),
		"Parameters":   in.Parameters,
	})
	cmd := exec.CommandContext(ctx, "session-manager-plugin", string(resp), t.cfg.Region, "StartSession", t.spec.Profile, string(req), "")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return fmt.Errorf("--plugin needs session-manager-plugin on PATH: %w", err)
		}
		return fmt.Errorf("session-manager-plugin: %w", err)
	}
	return nil
}

// ResolveCmd prints the instance a hostname selects.
type ResolveCmd struct {
	Host string `arg:"" help:"Hostname to resolve."`
}

func (c *ResolveCmd) Run(ctx context.Context, g *Globals, log *slog.Logger) error {
	t, err := resolveTarget(ctx, g, log, c.Host)
	if err != nil {
		return err
	}
	fmt.Printf("%s\tprofile=%s region=%s style=%s\n", t.match.InstanceID, t.spec.Profile, t.cfg.Region, t.match.Style)
	if t.match.Instance != nil {
		fmt.Printf("  %s\n", selector.Describe(*t.match.Instance, g.TagKey))
	}
	return nil
}

// ListCmd lists instances with the hostnames that select them.
type ListCmd struct {
	Profile string `arg:"" optional:"" help:"AWS profile to list (default: --profile, or the default profile)."`
}

func (c *ListCmd) Run(ctx context.Context, g *Globals, log *slog.Logger) error {
	profile := c.Profile
	if profile == "" {
		profile = g.Profile
	}
	cfg, err := loadAWSConfig(ctx, profile, g.Region)
	if err != nil {
		return err
	}
	r, err := newResolver(g, cfg)
	if err != nil {
		return err
	}
	instances, err := r.List(ctx)
	if err != nil {
		return withCredentialHint(err, profile)
	}

	// A slug is only usable when exactly one running instance has it.
	slugCount := map[string]int{}
	for _, inst := range instances {
		if isRunning(inst) {
			for _, s := range instanceSlugs(inst, g.TagKey) {
				slugCount[s]++
			}
		}
	}
	domain := hostDomain(profile, g)

	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "INSTANCE\tSTATE\tNAME\tPRIVATE IP\tPUBLIC IP\tHOSTNAME")
	for _, inst := range instances {
		host := aws.ToString(inst.InstanceId)
		for _, s := range instanceSlugs(inst, g.TagKey) {
			if slugCount[s] == 1 && isRunning(inst) {
				host = s
				break
			}
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			aws.ToString(inst.InstanceId), inst.State.Name, selector.TagValue(inst, g.TagKey[0]),
			dash(aws.ToString(inst.PrivateIpAddress)), dash(aws.ToString(inst.PublicIpAddress)), host+domain)
	}
	return tw.Flush()
}

func isRunning(inst types.Instance) bool {
	return inst.State != nil && inst.State.Name == types.InstanceStateNameRunning
}

// instanceSlugs returns the usable slugs of an instance's selector tags, skipping any that
// an earlier selection style would interpret differently.
func instanceSlugs(inst types.Instance, tagKeys []string) []string {
	var out []string
	for _, k := range tagKeys {
		s := selector.Slugify(selector.TagValue(inst, k))
		if s == "" || strings.HasPrefix(s, "i-") || strings.HasPrefix(s, "mi-") || strings.HasPrefix(s, "ip-") || hostspec.IsRegion(s) {
			continue
		}
		out = append(out, s)
	}
	return out
}

func hostDomain(profile string, g *Globals) string {
	var d string
	if g.Region != "" {
		d += "." + g.Region
	}
	if g.Profile == "" {
		if profile == "" {
			profile = "default"
		}
		d += "." + strings.ToLower(profile)
	}
	if len(g.Suffix) > 0 {
		d += "." + strings.Trim(g.Suffix[0], ".")
	}
	return d
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
