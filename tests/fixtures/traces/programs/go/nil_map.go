// SPDX-FileCopyrightText: 2026 The Nikasha Authors
// SPDX-License-Identifier: Apache-2.0

// Go fixture: assignment to an entry in a nil map.
package main

type registry struct {
	entries map[string]int
}

func (r *registry) add(name string) {
	r.entries[name]++
}

func register(r *registry, names []string) {
	for _, n := range names {
		r.add(n)
	}
}

func main() {
	register(&registry{}, []string{"a", "b"})
}
