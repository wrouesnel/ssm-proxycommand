package ssm_proxycommand

import (
	"context"
	"fmt"

	"github.com/wrouesnel/ctxstdio"

	"github.com/wrouesnel/ssm-proxycommand/pkg/selector"
)

// ResolveCmd prints the instance a hostname selects.
type ResolveCmd struct {
	Host string `arg:"" help:"Hostname to resolve."`
}

func (c *ResolveCmd) Run(ctx context.Context, g *Globals) error {
	t, err := resolveTarget(ctx, g, c.Host)
	if err != nil {
		return err
	}
	out := ctxstdio.StdOut(ctx)
	fmt.Fprintf(out, "%s\tprofile=%s region=%s style=%s\n", t.match.InstanceID, t.spec.Profile, t.cfg.Region, t.match.Style)
	if t.match.Instance != nil {
		fmt.Fprintf(out, "  %s\n", selector.Describe(*t.match.Instance, g.TagKey))
	}
	return nil
}
