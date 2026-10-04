// Package hostspec turns the hostname ssh hands a ProxyCommand into an instance selector, an AWS
// profile and an optional region.
//
// The accepted forms, after any configured suffix is removed, are:
//
//	<selector>.<profile>
//	<selector>.<region>.<profile>
//
// The selector may itself contain dots (IP addresses, DNS names). Profiles are matched without
// regard to case because ssh lowercases hostnames, and profile names containing dots are
// supported by preferring the longest known profile that ends the hostname.
package hostspec

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// Spec is a parsed hostname.
type Spec struct {
	Selector string
	Region   string // empty means the profile's configured region
	Profile  string // empty means the default credential chain
}

var regionRe = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-\d+$`)

// IsRegion reports whether s looks like an AWS region name.
func IsRegion(s string) bool { return regionRe.MatchString(s) }

// Options controls parsing.
type Options struct {
	// Suffixes are domain suffixes to strip first, e.g. "ssm" for hosts like web.prod.ssm.
	Suffixes []string
	// Profile, when set, is used for every host and the hostname is not searched for a profile.
	Profile string
	// Region, when set, overrides any region in the hostname.
	Region string
	// Profiles are the known profile names. Required unless Profile is set.
	Profiles []string
}

// Parse splits host according to opts.
func Parse(host string, opts Options) (Spec, error) {
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	for _, suf := range opts.Suffixes {
		suf = "." + strings.Trim(strings.ToLower(suf), ".")
		if strings.HasSuffix(h, suf) {
			h = strings.TrimSuffix(h, suf)
			break
		}
	}
	if h == "" {
		return Spec{}, errors.New("empty hostname")
	}

	var spec Spec
	if opts.Profile != "" {
		spec.Profile = opts.Profile
	} else {
		profile, rest, ok := matchProfile(h, opts.Profiles)
		if !ok {
			return Spec{}, fmt.Errorf("hostname %q does not end in a known AWS profile (expected <instance>.<profile>; known profiles: %s)",
				host, strings.Join(opts.Profiles, ", "))
		}
		spec.Profile = profile
		h = rest
	}

	// An optional region label sits between the selector and the profile.
	if i := strings.LastIndexByte(h, '.'); i > 0 && IsRegion(h[i+1:]) {
		spec.Region = h[i+1:]
		h = h[:i]
	}
	if opts.Region != "" {
		spec.Region = opts.Region
	}
	if h == "" {
		return Spec{}, fmt.Errorf("hostname %q has no instance selector", host)
	}
	spec.Selector = h
	return spec, nil
}

// matchProfile finds the longest known profile that forms the trailing labels of h, returning
// the profile's real (case-preserved) name and the remainder of the hostname.
func matchProfile(h string, profiles []string) (profile, rest string, ok bool) {
	best := -1
	for _, p := range profiles {
		lp := strings.ToLower(p)
		if !strings.HasSuffix(h, "."+lp) {
			continue
		}
		if len(lp) > best {
			best, profile, rest = len(lp), p, strings.TrimSuffix(h, "."+lp)
		}
	}
	return profile, rest, best >= 0
}

// KnownProfiles lists the profiles defined in the shared AWS config and credentials files,
// honouring AWS_CONFIG_FILE and AWS_SHARED_CREDENTIALS_FILE. "default" is always included since
// it can be satisfied by environment credentials alone.
func KnownProfiles() ([]string, error) {
	home, _ := os.UserHomeDir()
	configFile := envOr("AWS_CONFIG_FILE", filepath.Join(home, ".aws", "config"))
	credsFile := envOr("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(home, ".aws", "credentials"))

	set := map[string]bool{"default": true}
	if err := readSections(configFile, true, set); err != nil {
		return nil, err
	}
	if err := readSections(credsFile, false, set); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	slices.Sort(out)
	return out, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// readSections adds profile names from an INI file. In the config file, profiles other than
// default are written "[profile name]" and other section kinds (sso-session, services) are skipped.
func readSections(path string, isConfig bool, set map[string]bool) error {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "[") || !strings.HasSuffix(line, "]") {
			continue
		}
		name := strings.TrimSpace(line[1 : len(line)-1])
		if isConfig {
			switch {
			case name == "default":
			case strings.HasPrefix(name, "profile ") || strings.HasPrefix(name, "profile\t"):
				name = strings.TrimSpace(name[len("profile"):])
			default:
				continue
			}
		}
		if name != "" {
			set[name] = true
		}
	}
	return sc.Err()
}
