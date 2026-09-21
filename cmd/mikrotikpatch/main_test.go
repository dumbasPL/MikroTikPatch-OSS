package main

import (
	"reflect"
	"testing"
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
