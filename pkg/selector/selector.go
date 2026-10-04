// Package selector resolves a hostname-friendly instance selector to a single EC2 instance.
package selector

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// Style is a way of identifying an instance.
type Style string

const (
	StyleID         Style = "id"          // i-0123456789abcdef0, or mi-... for hybrid managed nodes
	StylePrivateIP  Style = "private-ip"  // 10.0.1.5 or ip-10-0-1-5, any ENI's private address
	StylePublicIP   Style = "public-ip"   // 203.0.113.7 or ip-203-0-113-7
	StylePrivateDNS Style = "private-dns" // ip-10-0-1-5.ec2.internal
	StylePublicDNS  Style = "public-dns"  // ec2-203-0-113-7.compute-1.amazonaws.com
	StyleTag        Style = "tag"         // a tag value, compared case-insensitively
	StyleSlug       Style = "slug"        // a slugified tag value: "Web Server (blue)" -> web-server-blue
)

// AllStyles is the default resolution order. Earlier styles win: a selector is only tried
// against a later style if no instance at all matched an earlier one.
var AllStyles = []Style{StyleID, StylePrivateIP, StylePublicIP, StylePrivateDNS, StylePublicDNS, StyleTag, StyleSlug}

// ParseStyles parses a list of style names.
func ParseStyles(names []string) ([]Style, error) {
	var out []Style
	for _, n := range names {
		s := Style(strings.ToLower(strings.TrimSpace(n)))
		if !slices.Contains(AllStyles, s) {
			return nil, fmt.Errorf("unknown selection style %q (valid: %s)", n, joinStyles(AllStyles))
		}
		out = append(out, s)
	}
	return out, nil
}

func joinStyles(styles []Style) string {
	s := make([]string, len(styles))
	for i, st := range styles {
		s[i] = string(st)
	}
	return strings.Join(s, ", ")
}

// EC2API is the subset of the EC2 client used for resolution.
type EC2API interface {
	DescribeInstances(ctx context.Context, in *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
}

// Resolver resolves selectors against one account and region.
type Resolver struct {
	EC2 EC2API
	// Styles are tried in order. Nil means AllStyles.
	Styles []Style
	// TagKeys are the tags used by the tag and slug styles. Nil means just "Name".
	TagKeys []string
}

// Match is a resolved instance.
type Match struct {
	InstanceID string
	Style      Style
	// Instance is nil for StyleID, which is resolved without an API call.
	Instance *types.Instance
}

// NotFoundError means no instance matched the selector in any enabled style.
type NotFoundError struct {
	Selector string
	Styles   []Style
}

func (e *NotFoundError) Error() string {
	return fmt.Sprintf("no instance matches %q (tried: %s)", e.Selector, joinStyles(e.Styles))
}

// AmbiguousError means more than one running instance matched.
type AmbiguousError struct {
	Selector   string
	Style      Style
	Candidates []types.Instance
	TagKeys    []string
}

func (e *AmbiguousError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%q is ambiguous: %d running instances match by %s; use one of their instance IDs:", e.Selector, len(e.Candidates), e.Style)
	for _, inst := range e.Candidates {
		fmt.Fprintf(&b, "\n  %s", Describe(inst, e.TagKeys))
	}
	return b.String()
}

// NotRunningError means instances matched, but none of them is running.
type NotRunningError struct {
	Selector   string
	Style      Style
	Candidates []types.Instance
	TagKeys    []string
}

func (e *NotRunningError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%q matches by %s, but no matching instance is running:", e.Selector, e.Style)
	for _, inst := range e.Candidates {
		fmt.Fprintf(&b, "\n  %s", Describe(inst, e.TagKeys))
	}
	return b.String()
}

var (
	instanceIDRe = regexp.MustCompile(`^i-([0-9a-f]{8}|[0-9a-f]{17})$`)
	managedIDRe  = regexp.MustCompile(`^mi-[0-9a-f]{17}$`)
	dashedIPRe   = regexp.MustCompile(`^ip-(\d{1,3})-(\d{1,3})-(\d{1,3})-(\d{1,3})$`)
)

// liveStates excludes terminated instances, which linger in DescribeInstances for a while.
var liveStates = []string{"pending", "running", "stopping", "stopped", "shutting-down"}

// Resolve finds the single running instance identified by selector.
func (r *Resolver) Resolve(ctx context.Context, selector string) (*Match, error) {
	sel := strings.ToLower(strings.TrimSpace(selector))
	styles := r.Styles
	if styles == nil {
		styles = AllStyles
	}
	tagKeys := r.tagKeys()

	var scan []types.Instance
	scanned := false
	for _, st := range styles {
		var (
			cands []types.Instance
			err   error
		)
		switch st {
		case StyleID:
			if instanceIDRe.MatchString(sel) || managedIDRe.MatchString(sel) {
				return &Match{InstanceID: sel, Style: StyleID}, nil
			}
			continue
		case StylePrivateIP, StylePublicIP:
			ip, ok := parseIP(sel)
			if !ok {
				continue
			}
			filter := "network-interface.addresses.private-ip-address"
			if st == StylePublicIP {
				filter = "ip-address"
			}
			cands, err = r.describe(ctx, filter, ip.String())
		case StylePrivateDNS, StylePublicDNS:
			if !strings.Contains(sel, ".") {
				continue
			}
			filter := "private-dns-name"
			if st == StylePublicDNS {
				filter = "dns-name"
			}
			cands, err = r.describe(ctx, filter, sel)
		case StyleTag, StyleSlug:
			if !scanned {
				if scan, err = r.describe(ctx, "tag-key", tagKeys...); err != nil {
					return nil, err
				}
				scanned = true
			}
			want := sel
			if st == StyleSlug {
				if want = Slugify(sel); want == "" {
					continue
				}
			}
			for _, inst := range scan {
				for _, k := range tagKeys {
					v, ok := tagValue(inst, k)
					if !ok {
						continue
					}
					if (st == StyleTag && strings.EqualFold(v, want)) || (st == StyleSlug && Slugify(v) == want) {
						cands = append(cands, inst)
						break
					}
				}
			}
		default:
			return nil, fmt.Errorf("unknown selection style %q", st)
		}
		if err != nil {
			return nil, err
		}
		if len(cands) == 0 {
			continue
		}
		return r.pick(selector, st, cands)
	}
	return nil, &NotFoundError{Selector: selector, Styles: styles}
}

func (r *Resolver) tagKeys() []string {
	if len(r.TagKeys) == 0 {
		return []string{"Name"}
	}
	return r.TagKeys
}

func (r *Resolver) pick(selector string, st Style, cands []types.Instance) (*Match, error) {
	var running []types.Instance
	for _, inst := range cands {
		if inst.State != nil && inst.State.Name == types.InstanceStateNameRunning {
			running = append(running, inst)
		}
	}
	switch len(running) {
	case 0:
		return nil, &NotRunningError{Selector: selector, Style: st, Candidates: cands, TagKeys: r.tagKeys()}
	case 1:
		inst := running[0]
		return &Match{InstanceID: aws.ToString(inst.InstanceId), Style: st, Instance: &inst}, nil
	default:
		return nil, &AmbiguousError{Selector: selector, Style: st, Candidates: running, TagKeys: r.tagKeys()}
	}
}

// describe lists live instances matching a single EC2 filter.
func (r *Resolver) describe(ctx context.Context, filter string, values ...string) ([]types.Instance, error) {
	in := &ec2.DescribeInstancesInput{
		Filters: []types.Filter{
			{Name: aws.String("instance-state-name"), Values: liveStates},
		},
	}
	if filter != "" {
		in.Filters = append(in.Filters, types.Filter{Name: aws.String(filter), Values: values})
	}
	return r.list(ctx, in)
}

// List returns every live instance in the region.
func (r *Resolver) List(ctx context.Context) ([]types.Instance, error) {
	return r.describe(ctx, "")
}

func (r *Resolver) list(ctx context.Context, in *ec2.DescribeInstancesInput) ([]types.Instance, error) {
	var out []types.Instance
	p := ec2.NewDescribeInstancesPaginator(r.EC2, in)
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describing EC2 instances: %w", err)
		}
		for _, res := range page.Reservations {
			out = append(out, res.Instances...)
		}
	}
	return out, nil
}

func parseIP(sel string) (netip.Addr, bool) {
	if m := dashedIPRe.FindStringSubmatch(sel); m != nil {
		sel = strings.Join(m[1:], ".")
	}
	ip, err := netip.ParseAddr(sel)
	if err != nil || !ip.Is4() {
		return netip.Addr{}, false
	}
	return ip, true
}

func tagValue(inst types.Instance, key string) (string, bool) {
	for _, t := range inst.Tags {
		if aws.ToString(t.Key) == key {
			return aws.ToString(t.Value), true
		}
	}
	return "", false
}

// TagValue returns the value of tag key on inst, or "".
func TagValue(inst types.Instance, key string) string {
	v, _ := tagValue(inst, key)
	return v
}

// Slugify lowercases s and replaces each run of characters other than a-z and 0-9 with a
// single hyphen, trimming hyphens from the ends. The result is always a valid DNS label body.
func Slugify(s string) string {
	var b strings.Builder
	pendingDash := false
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			if pendingDash && b.Len() > 0 {
				b.WriteByte('-')
			}
			pendingDash = false
			b.WriteRune(r)
			continue
		}
		pendingDash = true
	}
	return b.String()
}

// Describe summarises an instance on one line for error messages and listings.
func Describe(inst types.Instance, tagKeys []string) string {
	parts := []string{aws.ToString(inst.InstanceId)}
	if inst.State != nil {
		parts = append(parts, string(inst.State.Name))
	}
	for _, k := range tagKeys {
		if v, ok := tagValue(inst, k); ok {
			parts = append(parts, fmt.Sprintf("%s=%q", k, v))
		}
	}
	if ip := aws.ToString(inst.PrivateIpAddress); ip != "" {
		parts = append(parts, ip)
	}
	return strings.Join(parts, "  ")
}

// IsResolutionError reports whether err is a selector problem (as opposed to an AWS failure).
func IsResolutionError(err error) bool {
	var nf *NotFoundError
	var am *AmbiguousError
	var nr *NotRunningError
	return errors.As(err, &nf) || errors.As(err, &am) || errors.As(err, &nr)
}
