package ssmsession

import "testing"

func TestVersionAtLeast(t *testing.T) {
	for _, tc := range []struct {
		v, min string
		want   bool
	}{
		{"3.3.0.0", "2.3.722.0", true},
		{"2.3.722.0", "2.3.722.0", true},
		{"2.3.68.0", "2.3.722.0", false},
		{"2.10", "2.3.722.0", true},
		{"garbage", "2.3.722.0", true},
	} {
		if got := versionAtLeast(tc.v, tc.min); got != tc.want {
			t.Errorf("versionAtLeast(%q, %q) = %v", tc.v, tc.min, got)
		}
	}
}
