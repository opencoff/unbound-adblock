// reverse.go -- reverse a string slice
//
// (c) 2018 Sudhi Herle
//
// License: GPLv2

package blgen

// reverse a string slice and return it.
// This reverses in-place.
func reverse(v []string) []string {
	for i, j := 0, len(v)-1; i < j; i, j = i+1, j-1 {
		v[i], v[j] = v[j], v[i]
	}

	return v
}

// vim: ft=go:sw=8:ts=8:noexpandtab:tw=98:
