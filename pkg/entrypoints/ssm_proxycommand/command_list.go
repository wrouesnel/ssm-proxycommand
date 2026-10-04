package ssm_proxycommand

import (
	"context"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/wrouesnel/ctxstdio"

	"github.com/wrouesnel/ssm-proxycommand/pkg/hostspec"
	"github.com/wrouesnel/ssm-proxycommand/pkg/selector"
)

// ListCmd lists instances with the hostnames that select them.
type ListCmd struct {
	Profile string `arg:"" help:"AWS profile to list (default: --profile, or the default profile)." optional:""`
}

func (c *ListCmd) Run(ctx context.Context, g *Globals) error {
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

	tw := tabwriter.NewWriter(ctxstdio.StdOut(ctx), 0, 4, 2, ' ', 0)
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
