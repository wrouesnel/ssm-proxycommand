package hostspec

import (
	"slices"
	"testing"

	"github.com/spf13/afero"
)

func TestParse(t *testing.T) {
	profiles := []string{"default", "prod", "Dev", "corp.staging", "staging"}
	for _, tc := range []struct {
		host string
		opts Options
		want Spec
		err  bool
	}{
		{host: "i-0123456789abcdef0.prod", want: Spec{Selector: "i-0123456789abcdef0", Profile: "prod"}},
		{host: "web-server.dev", want: Spec{Selector: "web-server", Profile: "Dev"}},
		{host: "WEB-Server.DEV.", want: Spec{Selector: "web-server", Profile: "Dev"}},
		{host: "10.0.1.5.prod", want: Spec{Selector: "10.0.1.5", Profile: "prod"}},
		{host: "web.ap-southeast-2.prod", want: Spec{Selector: "web", Region: "ap-southeast-2", Profile: "prod"}},
		{host: "web.us-gov-west-1.prod", want: Spec{Selector: "web", Region: "us-gov-west-1", Profile: "prod"}},
		{host: "ip-10-0-0-1.ap-southeast-2.compute.internal.prod", want: Spec{Selector: "ip-10-0-0-1.ap-southeast-2.compute.internal", Profile: "prod"}},
		{host: "web.corp.staging", want: Spec{Selector: "web", Profile: "corp.staging"}},
		{host: "web.staging", want: Spec{Selector: "web", Profile: "staging"}},
		{host: "web.prod.ssm", opts: Options{Suffixes: []string{"ssm"}}, want: Spec{Selector: "web", Profile: "prod"}},
		{host: "web.prod.ssm.example.com", opts: Options{Suffixes: []string{".ssm.example.com."}}, want: Spec{Selector: "web", Profile: "prod"}},
		{host: "web.eu-west-1", opts: Options{Profile: "fixed"}, want: Spec{Selector: "web", Region: "eu-west-1", Profile: "fixed"}},
		{host: "web.eu-west-1.prod", opts: Options{Region: "us-east-1"}, want: Spec{Selector: "web", Region: "us-east-1", Profile: "prod"}},
		{host: "web.unknown", err: true},
		{host: "prod", err: true},
		{host: "eu-west-1.prod", want: Spec{Selector: "eu-west-1", Profile: "prod"}},
		{host: "", err: true},
	} {
		opts := tc.opts
		opts.Profiles = profiles
		got, err := Parse(tc.host, opts)
		if tc.err {
			if err == nil {
				t.Errorf("Parse(%q) = %+v, want error", tc.host, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("Parse(%q): %v", tc.host, err)
			continue
		}
		if got != tc.want {
			t.Errorf("Parse(%q) = %+v, want %+v", tc.host, got, tc.want)
		}
	}
}

func TestKnownProfiles(t *testing.T) {
	fs := afero.NewMemMapFs()
	cfg, creds := "/aws/config", "/aws/credentials"
	if err := afero.WriteFile(fs, cfg, []byte(`
[default]
region = us-east-1
[profile prod]
region = ap-southeast-2
[profile  Dev ]
[sso-session corp]
sso_start_url = https://example.awsapps.com/start
[services local]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := afero.WriteFile(fs, creds, []byte("[legacy]\naws_access_key_id = x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CONFIG_FILE", cfg)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", creds)

	got, err := KnownProfiles(fs)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"Dev", "default", "legacy", "prod"}
	if !slices.Equal(got, want) {
		t.Fatalf("KnownProfiles = %v, want %v", got, want)
	}

	// Missing files are not an error.
	t.Setenv("AWS_CONFIG_FILE", "/nope/config")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "/nope/credentials")
	got, err = KnownProfiles(fs)
	if err != nil {
		t.Fatal(err)
	}
	want = []string{"default"}
	if !slices.Equal(got, want) {
		t.Fatalf("KnownProfiles = %v, want %v", got, want)
	}
}
