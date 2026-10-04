package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/wrouesnel/ssm-proxycommand/internal/fakeaws"
)

// e2eEnv runs the real OpenSSH client with this binary as its ProxyCommand, against fake EC2
// and SSM endpoints whose sessions forward to an in-process SSH server.
type e2eEnv struct {
	t      *testing.T
	bin    string
	key    string
	api    *fakeaws.API
	env    []string
	config string
}

func newE2E(t *testing.T) *e2eEnv {
	t.Helper()
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh client not installed")
	}
	dir := t.TempDir()

	bin := filepath.Join(dir, "ssm-proxycommand")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("building: %v\n%s", err, out)
	}

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	sshPub, _ := ssh.NewPublicKey(pub)
	sshd, err := fakeaws.StartSSHServer(sshPub)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sshd.Close)

	api := &fakeaws.API{
		Target: sshd.Addr,
		Instances: []fakeaws.Instance{
			{ID: "i-00000000000000001", State: "running", PrivateIP: "10.0.0.1", Tags: map[string]string{"Name": "bastion"}},
			{ID: "i-00000000000000002", State: "running", PrivateIP: "10.0.0.2", PublicIP: "203.0.113.2", Tags: map[string]string{"Name": "Web Server"}},
			{ID: "i-00000000000000003", State: "running", PrivateIP: "10.0.0.3", Tags: map[string]string{"Name": "dupe"}},
			{ID: "i-00000000000000004", State: "running", PrivateIP: "10.0.0.4", Tags: map[string]string{"Name": "Dupe"}},
			{ID: "i-00000000000000005", State: "stopped", PrivateIP: "10.0.0.5", Tags: map[string]string{"Name": "sleepy"}},
		},
	}
	endpoint := api.Start()
	t.Cleanup(func() {
		api.Close()
		for _, e := range api.AgentErrors() {
			t.Errorf("fake agent: %s", e)
		}
	})

	cfg := filepath.Join(dir, "config")
	creds := filepath.Join(dir, "credentials")
	os.WriteFile(cfg, []byte("[profile e2e]\nregion = us-east-1\n[profile Other.Team]\nregion = eu-west-1\n"), 0o600)
	os.WriteFile(creds, []byte("[e2e]\naws_access_key_id = AKIDTEST\naws_secret_access_key = secret\n"+
		"[Other.Team]\naws_access_key_id = AKIDTEST\naws_secret_access_key = secret\n"), 0o600)

	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + dir,
		"AWS_CONFIG_FILE=" + cfg,
		"AWS_SHARED_CREDENTIALS_FILE=" + creds,
		"AWS_ENDPOINT_URL=" + endpoint,
		"AWS_EC2_METADATA_DISABLED=true",
	}
	sshConfig := filepath.Join(dir, "ssh_config")
	os.WriteFile(sshConfig, []byte(strings.Join([]string{
		"Host *.ssm",
		"  ProxyCommand " + bin + " --suffix=ssm --log-file=" + filepath.Join(dir, "proxy.log") + " -vv %h %p",
		"  User tester",
		"  IdentityFile " + keyFile,
		"  IdentitiesOnly yes",
		"  BatchMode yes",
		"  StrictHostKeyChecking no",
		"  UserKnownHostsFile /dev/null",
		"  LogLevel ERROR",
		"",
	}, "\n")), 0o600)

	return &e2eEnv{t: t, bin: bin, key: keyFile, api: api, env: env, config: sshConfig}
}

func (e *e2eEnv) ssh(host string, stdin []byte, command string) (string, string, error) {
	cmd := exec.Command("ssh", "-F", e.config, host, command)
	cmd.Env = e.env
	cmd.Stdin = bytes.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		return "", "", err
	}
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return stdout.String(), stderr.String(), err
	case <-time.After(60 * time.Second):
		_ = cmd.Process.Kill()
		e.t.Fatalf("ssh %s timed out; stderr: %s", host, stderr.String())
		return "", "", nil
	}
}

func TestE2ESSH(t *testing.T) {
	e := newE2E(t)

	data := make([]byte, 2<<20)
	_, _ = rand.Read(data)
	for _, tc := range []struct {
		host   string
		target string
	}{
		{"web-server.e2e.ssm", "i-00000000000000002"},
		{"Web-Server.E2E.ssm", "i-00000000000000002"},
		{"bastion.us-east-1.e2e.ssm", "i-00000000000000001"},
		{"i-00000000000000003.e2e.ssm", "i-00000000000000003"},
		{"10.0.0.4.e2e.ssm", "i-00000000000000004"},
		{"ip-10-0-0-1.e2e.ssm", "i-00000000000000001"},
		{"203.0.113.2.e2e.ssm", "i-00000000000000002"},
		{"bastion.other.team.ssm", "i-00000000000000001"},
	} {
		t.Run(tc.host, func(t *testing.T) {
			before := len(e.api.Started())
			out, stderr, err := e.ssh(tc.host, data, "wc -c")
			if err != nil {
				t.Fatalf("ssh: %v\nstderr: %s", err, stderr)
			}
			if strings.TrimSpace(out) != "2097152" {
				t.Fatalf("remote saw %q bytes, want 2097152; stderr: %s", out, stderr)
			}
			started := e.api.Started()
			if len(started) != before+1 {
				t.Fatalf("expected one new session, got %d", len(started)-before)
			}
			s := started[len(started)-1]
			if s.Target != tc.target || s.DocumentName != "AWS-StartSSHSession" || s.Parameters["portNumber"][0] != "22" {
				t.Fatalf("StartSession = %+v, want target %s", s, tc.target)
			}
			waitFor(t, func() bool { return contains(e.api.Terminated(), s.SessionID) }, "session terminated via API")
		})
	}
}

func TestE2ESelectionErrors(t *testing.T) {
	e := newE2E(t)
	for host, want := range map[string]string{
		"dupe.e2e.ssm":      "ambiguous",
		"sleepy.e2e.ssm":    "no matching instance is running",
		"missing.e2e.ssm":   "no instance matches",
		"web.nosuch.ssm":    "does not end in a known AWS profile",
		"web.e2e.elsewhere": "",
	} {
		t.Run(host, func(t *testing.T) {
			_, stderr, err := e.ssh(host, nil, "true")
			if err == nil {
				t.Fatal("ssh succeeded")
			}
			if want != "" && !strings.Contains(stderr, want) {
				t.Fatalf("stderr %q does not mention %q", stderr, want)
			}
		})
	}
	if n := len(e.api.Started()); n != 0 {
		t.Fatalf("%d sessions started for unresolvable hosts", n)
	}
}

func TestE2EList(t *testing.T) {
	e := newE2E(t)
	cmd := exec.Command(e.bin, "--suffix=ssm", "list", "e2e")
	cmd.Env = e.env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("list: %v\n%s", err, out)
	}
	for _, want := range []string{
		"web-server.e2e.ssm",
		"bastion.e2e.ssm",
		"i-00000000000000003.e2e.ssm", // "dupe" is ambiguous, so the ID is offered
		"i-00000000000000005.e2e.ssm", // stopped
	} {
		if !strings.Contains(string(out), want) {
			t.Errorf("list output lacks %q:\n%s", want, out)
		}
	}

	cmd = exec.Command(e.bin, "--suffix=ssm", "resolve", "web-server.e2e.ssm")
	cmd.Env = e.env
	out, err = cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "i-00000000000000002") || !strings.Contains(string(out), "style=slug") {
		t.Fatalf("resolve: %v\n%s", err, out)
	}
}

func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
