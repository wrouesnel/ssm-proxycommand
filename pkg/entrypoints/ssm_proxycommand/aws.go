package ssm_proxycommand

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/spf13/afero"
	logutil "github.com/wrouesnel/go.logutil"
	"go.uber.org/zap"

	"github.com/wrouesnel/ssm-proxycommand/pkg/hostspec"
	"github.com/wrouesnel/ssm-proxycommand/pkg/selector"
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
		profiles, err := hostspec.KnownProfiles(afero.NewOsFs())
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

func resolveTarget(ctx context.Context, g *Globals, host string) (*target, error) {
	log := logutil.FromCtx(ctx)
	spec, err := parseHost(g, host)
	if err != nil {
		return nil, err
	}
	log.Debug("parsed hostname", zap.String("selector", spec.Selector), zap.String("profile", spec.Profile), zap.String("region", spec.Region))
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
	log.Info("resolved instance", zap.String("instance", m.InstanceID), zap.String("style", string(m.Style)),
		zap.String("profile", spec.Profile), zap.String("region", cfg.Region))
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
