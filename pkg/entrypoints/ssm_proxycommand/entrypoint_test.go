package ssm_proxycommand_test

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wrouesnel/ctxstdio"

	"github.com/wrouesnel/ssm-proxycommand/internal/fakeaws"
	"github.com/wrouesnel/ssm-proxycommand/pkg/entrypoints/ssm_proxycommand"
	"github.com/wrouesnel/ssm-proxycommand/version"
)

// runEntrypoint invokes the entrypoint as though from the command line and captures its output.
func runEntrypoint(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	stdOut, stdErr := new(bytes.Buffer), new(bytes.Buffer)
	ctx := ctxstdio.Set(context.Background(), stdOut, stdErr, io.NopCloser(strings.NewReader("")))
	exitCode := ssm_proxycommand.Entrypoint(ctx, args)
	return exitCode, stdOut.String(), stdErr.String()
}

// fakeAccount points the AWS SDK at fake EC2 and SSM endpoints with a profile named "e2e".
func fakeAccount(t *testing.T) *fakeaws.API {
	t.Helper()
	api := &fakeaws.API{
		Target: "127.0.0.1:1",
		Instances: []fakeaws.Instance{
			{ID: "i-00000000000000001", State: "running", PrivateIP: "10.0.0.1", Tags: map[string]string{"Name": "bastion"}},
			{ID: "i-00000000000000002", State: "running", PrivateIP: "10.0.0.2", PublicIP: "203.0.113.2", Tags: map[string]string{"Name": "Web Server"}},
			{ID: "i-00000000000000003", State: "running", PrivateIP: "10.0.0.3", Tags: map[string]string{"Name": "dupe"}},
			{ID: "i-00000000000000004", State: "running", PrivateIP: "10.0.0.4", Tags: map[string]string{"Name": "Dupe"}},
			{ID: "i-00000000000000005", State: "stopped", PrivateIP: "10.0.0.5", Tags: map[string]string{"Name": "sleepy"}},
		},
	}
	endpoint := api.Start()
	t.Cleanup(api.Close)

	dir := t.TempDir()
	cfg := filepath.Join(dir, "config")
	creds := filepath.Join(dir, "credentials")
	if err := os.WriteFile(cfg, []byte("[profile e2e]\nregion = us-east-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(creds, []byte("[e2e]\naws_access_key_id = AKIDTEST\naws_secret_access_key = secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Isolate from the developer's own AWS environment.
	for _, v := range []string{"AWS_REGION", "AWS_DEFAULT_REGION", "AWS_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"} {
		t.Setenv(v, "")
	}
	t.Setenv("AWS_CONFIG_FILE", cfg)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", creds)
	t.Setenv("AWS_ENDPOINT_URL", endpoint)
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	return api
}

func TestVersion(t *testing.T) {
	exitCode, stdOut, _ := runEntrypoint(t, "--version")
	if exitCode != 0 {
		t.Fatalf("exit code: got %d, want 0", exitCode)
	}
	if !strings.Contains(stdOut, version.Version) {
		t.Errorf("stdout %q does not contain version %q", stdOut, version.Version)
	}
}

func TestInvalidFlagFails(t *testing.T) {
	exitCode, _, stdErr := runEntrypoint(t, "--no-such-flag")
	if exitCode == 0 {
		t.Fatal("exit code: got 0, want non-zero")
	}
	if !strings.Contains(stdErr, "no-such-flag") {
		t.Errorf("stderr %q does not mention the bad flag", stdErr)
	}
}

func TestInvalidStyleFails(t *testing.T) {
	fakeAccount(t)
	exitCode, _, stdErr := runEntrypoint(t, "--styles=id,bogus", "resolve", "web.e2e")
	if exitCode != 1 || !strings.Contains(stdErr, `unknown selection style "bogus"`) {
		t.Fatalf("exit %d, stderr %q", exitCode, stdErr)
	}
}

func TestList(t *testing.T) {
	fakeAccount(t)
	exitCode, out, stdErr := runEntrypoint(t, "--suffix=ssm", "list", "e2e")
	if exitCode != 0 {
		t.Fatalf("list: exit %d\n%s", exitCode, stdErr)
	}
	for _, want := range []string{
		"web-server.e2e.ssm",
		"bastion.e2e.ssm",
		"i-00000000000000003.e2e.ssm", // "dupe" is ambiguous, so the ID is offered
		"i-00000000000000005.e2e.ssm", // stopped
	} {
		if !strings.Contains(out, want) {
			t.Errorf("list output lacks %q:\n%s", want, out)
		}
	}
}

func TestResolve(t *testing.T) {
	fakeAccount(t)
	for host, want := range map[string]string{
		"web-server.e2e.ssm":             "i-00000000000000002\tprofile=e2e region=us-east-1 style=slug",
		"bastion.ap-southeast-2.e2e.ssm": "region=ap-southeast-2 style=tag",
		"ip-10-0-0-3.e2e.ssm":            "i-00000000000000003\tprofile=e2e region=us-east-1 style=private-ip",
	} {
		exitCode, out, stdErr := runEntrypoint(t, "--suffix=ssm", "resolve", host)
		if exitCode != 0 || !strings.Contains(out, want) {
			t.Errorf("resolve %s: exit %d, stdout %q, stderr %q; want %q", host, exitCode, out, stdErr, want)
		}
	}
}

func TestEnvironmentVariables(t *testing.T) {
	fakeAccount(t)
	t.Setenv("SSM_PROXYCOMMAND_SUFFIX", "ssm")
	t.Setenv("SSM_PROXYCOMMAND_STYLES", "slug")
	exitCode, out, stdErr := runEntrypoint(t, "resolve", "web-server.e2e.ssm")
	if exitCode != 0 || !strings.Contains(out, "style=slug") {
		t.Fatalf("exit %d, stdout %q, stderr %q", exitCode, out, stdErr)
	}
}

func TestProxySelectionErrors(t *testing.T) {
	api := fakeAccount(t)
	for host, want := range map[string]string{
		"dupe.e2e":    "ambiguous",
		"sleepy.e2e":  "no matching instance is running",
		"missing.e2e": "no instance matches",
		"web.nosuch":  "does not end in a known AWS profile",
	} {
		exitCode, _, stdErr := runEntrypoint(t, host, "22")
		if exitCode != 1 || !strings.Contains(stdErr, want) {
			t.Errorf("%s: exit %d, stderr %q; want mention of %q", host, exitCode, stdErr, want)
		}
	}
	if n := len(api.Started()); n != 0 {
		t.Fatalf("%d sessions started for unresolvable hosts", n)
	}
}
