package main

import (
	"flag"
	"reflect"
	"testing"
	"time"
)

func TestParseArchs(t *testing.T) {
	cases := []struct {
		in    string
		want  []string
		isErr bool
	}{
		{in: "all", want: []string{"x86", "arm64"}},
		{in: "ALL", want: []string{"x86", "arm64"}},
		{in: "x86", want: []string{"x86"}},
		{in: "arm64", want: []string{"arm64"}},
		{in: "x86,arm64", want: []string{"x86", "arm64"}},
		{in: "arm64,x86", want: []string{"arm64", "x86"}},
		{in: " x86 , arm64 ", want: []string{"x86", "arm64"}},
		{in: "", isErr: true},
		{in: ",", isErr: true},
		// Unknown names are rejected up front instead of failing later in
		// keygen/build.sh or on a 404 ISO download.
		{in: "x68", isErr: true},
		{in: "x86,i386", isErr: true},
		// JSON arrays are not supported; they are not architecture names.
		{in: `["x86"]`, isErr: true},
		// Duplicates would run the same architecture twice in parallel.
		{in: "x86,x86", isErr: true},
	}
	for _, tc := range cases {
		got, err := parseArchs(tc.in)
		if tc.isErr {
			if err == nil {
				t.Errorf("parseArchs(%q) = %v, want an error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseArchs(%q): %v", tc.in, err)
			continue
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("parseArchs(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// The timeouts are documented in seconds, so a bare number must be accepted
// (Go's flag.Duration alone rejects "600").
func TestParseSeconds(t *testing.T) {
	cases := []struct {
		in    string
		want  time.Duration
		isErr bool
	}{
		{in: "1800", want: 1800 * time.Second},
		{in: "600", want: 600 * time.Second},
		{in: "0", want: 0},
		{in: "0.5", want: 500 * time.Millisecond},
		{in: " 90 ", want: 90 * time.Second},
		{in: "600s", want: 600 * time.Second},
		{in: "10m", want: 10 * time.Minute},
		{in: "1h30m", want: 90 * time.Minute},
		{in: "", isErr: true},
		{in: "abc", isErr: true},
		{in: "10 minutes", isErr: true},
	}
	for _, tc := range cases {
		got, err := parseSeconds(tc.in)
		if tc.isErr {
			if err == nil {
				t.Errorf("parseSeconds(%q) = %v, want an error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseSeconds(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseSeconds(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestSecondsFlag(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want time.Duration
	}{
		{in: "1800", want: 1800 * time.Second},
		{in: "30m", want: 30 * time.Minute},
	} {
		var got time.Duration
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		fs.Var(secondsFlag{&got}, "boot-test-timeout", "")
		if err := fs.Parse([]string{"--boot-test-timeout", tc.in}); err != nil {
			t.Errorf("parse %q: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("--boot-test-timeout %q = %v, want %v", tc.in, got, tc.want)
		}
	}
}
