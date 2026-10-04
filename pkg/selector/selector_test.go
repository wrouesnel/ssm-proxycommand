package selector

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// fakeEC2 implements the DescribeInstances filters the resolver uses, paging two at a time.
type fakeEC2 struct {
	instances []types.Instance
	calls     int
}

func (f *fakeEC2) DescribeInstances(ctx context.Context, in *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	f.calls++
	var matched []types.Instance
	for _, inst := range f.instances {
		if matchesAll(inst, in.Filters) {
			matched = append(matched, inst)
		}
	}
	start := 0
	if in.NextToken != nil {
		start = int((*in.NextToken)[0] - '0')
	}
	end := min(start+2, len(matched))
	out := &ec2.DescribeInstancesOutput{Reservations: []types.Reservation{{Instances: matched[start:end]}}}
	if end < len(matched) {
		out.NextToken = aws.String(string(rune('0' + end)))
	}
	return out, nil
}

func matchesAll(inst types.Instance, filters []types.Filter) bool {
	for _, f := range filters {
		var have []string
		switch aws.ToString(f.Name) {
		case "instance-state-name":
			have = []string{string(inst.State.Name)}
		case "network-interface.addresses.private-ip-address":
			for _, ni := range inst.NetworkInterfaces {
				for _, a := range ni.PrivateIpAddresses {
					have = append(have, aws.ToString(a.PrivateIpAddress))
				}
			}
		case "ip-address":
			have = []string{aws.ToString(inst.PublicIpAddress)}
		case "private-dns-name":
			have = []string{aws.ToString(inst.PrivateDnsName)}
		case "dns-name":
			have = []string{aws.ToString(inst.PublicDnsName)}
		case "tag-key":
			for _, t := range inst.Tags {
				have = append(have, aws.ToString(t.Key))
			}
		default:
			panic("unexpected filter " + aws.ToString(f.Name))
		}
		if !slices.ContainsFunc(have, func(h string) bool { return slices.Contains(f.Values, h) }) {
			return false
		}
	}
	return true
}

func inst(id, state, privIP, pubIP string, tags ...string) types.Instance {
	i := types.Instance{
		InstanceId:       aws.String(id),
		State:            &types.InstanceState{Name: types.InstanceStateName(state)},
		PrivateIpAddress: aws.String(privIP),
		PrivateDnsName:   aws.String("ip-" + strings.ReplaceAll(privIP, ".", "-") + ".ap-southeast-2.compute.internal"),
		NetworkInterfaces: []types.InstanceNetworkInterface{{
			PrivateIpAddresses: []types.InstancePrivateIpAddress{{PrivateIpAddress: aws.String(privIP)}},
		}},
	}
	if pubIP != "" {
		i.PublicIpAddress = aws.String(pubIP)
		i.PublicDnsName = aws.String("ec2-" + strings.ReplaceAll(pubIP, ".", "-") + ".ap-southeast-2.compute.amazonaws.com")
	}
	for k := 0; k+1 < len(tags); k += 2 {
		i.Tags = append(i.Tags, types.Tag{Key: aws.String(tags[k]), Value: aws.String(tags[k+1])})
	}
	return i
}

func fixture() *fakeEC2 {
	return &fakeEC2{instances: []types.Instance{
		inst("i-00000000000000001", "running", "10.0.0.1", "203.0.113.1", "Name", "Web Server (Blue)", "Role", "web"),
		inst("i-00000000000000002", "running", "10.0.0.2", "", "Name", "web_server_blue"),
		inst("i-00000000000000003", "running", "10.0.0.3", "", "Name", "bastion"),
		inst("i-00000000000000004", "stopped", "10.0.0.4", "", "Name", "Old Box"),
		inst("i-00000000000000005", "running", "10.0.0.5", "", "Name", "worker"),
		inst("i-00000000000000006", "running", "10.0.0.6", "", "Name", "Worker"),
		inst("i-00000000000000007", "running", "10.0.0.7", "", "Name", "db.primary", "Hostname", "pg-1"),
	}}
}

func TestResolve(t *testing.T) {
	for _, tc := range []struct {
		sel     string
		styles  []Style
		tagKeys []string
		wantID  string
		want    Style
	}{
		{sel: "i-00000000000000003", wantID: "i-00000000000000003", want: StyleID},
		{sel: "I-0123ABCD", wantID: "i-0123abcd", want: StyleID},
		{sel: "mi-0123456789abcdef0", wantID: "mi-0123456789abcdef0", want: StyleID},
		{sel: "10.0.0.3", wantID: "i-00000000000000003", want: StylePrivateIP},
		{sel: "ip-10-0-0-3", wantID: "i-00000000000000003", want: StylePrivateIP},
		{sel: "203.0.113.1", wantID: "i-00000000000000001", want: StylePublicIP},
		{sel: "ip-10-0-0-5.ap-southeast-2.compute.internal", wantID: "i-00000000000000005", want: StylePrivateDNS},
		{sel: "ec2-203-0-113-1.ap-southeast-2.compute.amazonaws.com", wantID: "i-00000000000000001", want: StylePublicDNS},
		{sel: "bastion", wantID: "i-00000000000000003", want: StyleTag},
		{sel: "BASTION", wantID: "i-00000000000000003", want: StyleTag},
		// An exact tag match beats a slug match that would otherwise be ambiguous.
		{sel: "web_server_blue", wantID: "i-00000000000000002", want: StyleTag},
		{sel: "db.primary", wantID: "i-00000000000000007", want: StyleTag},
		{sel: "db-primary", wantID: "i-00000000000000007", want: StyleSlug},
		{sel: "pg-1", tagKeys: []string{"Name", "Hostname"}, wantID: "i-00000000000000007", want: StyleTag},
		// Restricting styles skips the exact tag stage.
		{sel: "bastion", styles: []Style{StyleSlug}, wantID: "i-00000000000000003", want: StyleSlug},
	} {
		f := fixture()
		r := &Resolver{EC2: f, Styles: tc.styles, TagKeys: tc.tagKeys}
		m, err := r.Resolve(context.Background(), tc.sel)
		if err != nil {
			t.Errorf("Resolve(%q): %v", tc.sel, err)
			continue
		}
		if m.InstanceID != tc.wantID || m.Style != tc.want {
			t.Errorf("Resolve(%q) = %s by %s, want %s by %s", tc.sel, m.InstanceID, m.Style, tc.wantID, tc.want)
		}
		if m.Style == StyleID && f.calls != 0 {
			t.Errorf("Resolve(%q) made %d API calls for an instance ID", tc.sel, f.calls)
		}
	}
}

func TestResolveErrors(t *testing.T) {
	r := &Resolver{EC2: fixture()}

	_, err := r.Resolve(context.Background(), "web-server-blue")
	var am *AmbiguousError
	if !errors.As(err, &am) || am.Style != StyleSlug || len(am.Candidates) != 2 {
		t.Fatalf("slug collision: got %v", err)
	}
	if !strings.Contains(err.Error(), "i-00000000000000001") || !strings.Contains(err.Error(), "i-00000000000000002") {
		t.Errorf("ambiguity error does not list candidates: %v", err)
	}

	// Case-insensitive tag matching can be ambiguous too.
	if _, err := r.Resolve(context.Background(), "worker"); !errors.As(err, &am) || am.Style != StyleTag {
		t.Fatalf("tag collision: got %v", err)
	}

	var nr *NotRunningError
	if _, err := r.Resolve(context.Background(), "old-box"); !errors.As(err, &nr) {
		t.Fatalf("stopped instance: got %v", err)
	}

	var nf *NotFoundError
	if _, err := r.Resolve(context.Background(), "nope"); !errors.As(err, &nf) {
		t.Fatalf("missing instance: got %v", err)
	}
	if _, err := r.Resolve(context.Background(), "10.9.9.9"); !errors.As(err, &nf) {
		t.Fatalf("unknown IP: got %v", err)
	}

	// Restricting styles disables the others.
	r.Styles = []Style{StyleTag}
	if _, err := r.Resolve(context.Background(), "i-00000000000000003"); !errors.As(err, &nf) {
		t.Fatalf("id with tag-only styles: got %v", err)
	}
}

func TestSlugify(t *testing.T) {
	for in, want := range map[string]string{
		"Web Server (Blue)": "web-server-blue",
		"web_server_blue":   "web-server-blue",
		"--a--b--":          "a-b",
		"db.primary":        "db-primary",
		"Ünïcødé box":       "n-c-d-box",
		"!!!":               "",
	} {
		if got := Slugify(in); got != want {
			t.Errorf("Slugify(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseStyles(t *testing.T) {
	s, err := ParseStyles([]string{"ID", " slug"})
	if err != nil || !slices.Equal(s, []Style{StyleID, StyleSlug}) {
		t.Fatalf("ParseStyles = %v, %v", s, err)
	}
	if _, err := ParseStyles([]string{"bogus"}); err == nil {
		t.Fatal("ParseStyles accepted an unknown style")
	}
}
