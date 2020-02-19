// domainsort.go -- sort a list of domain names by suffix
//
// (c) 2018 Sudhi Herle
//
// License: GPLv2

package blacklist

import (
	"sort"
)

// break a domain into its parts - and return slice - pointing back
// to the original string
func parts(s string) []string {
	i := 0
	j := 0
	n := len(s)

	var v []string
	for i = 0; i < n; i++ {
		if s[i] == '.' {
			t := s[j:i]
			j = i + 1
			v = append(v, t)
		}
	}

	return append(v, s[j:i])
}

type ByDomains []string

func (d ByDomains) Len() int      { return len(d) }
func (d ByDomains) Swap(i, j int) { d[i], d[j] = d[j], d[i] }

// We order domains by suffix and then lexicographically and finally
// by # of sub-parts in the name
func (d ByDomains) Less(i, j int) bool {
	p := reverse(parts(d[i]))
	q := reverse(parts(d[j]))

	a := len(p)
	b := len(q)
	var z int

	if a < b {
		z = a
	} else {
		z = b
	}

	for k := 0; k < z; k++ {
		m, n := p[k], q[k]

		if m == n {
			continue
		}
		if m < n {
			return true
		}
		if m > n {
			return false
		}
	}

	if a < b {
		return true
	}

	return false
}

func domSort(d []string) []string {
	sort.Sort(ByDomains(d))
	return d
}

// vim: ft=go:sw=8:ts=8:noexpandtab:tw=98:
