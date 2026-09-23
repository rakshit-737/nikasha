// SPDX-FileCopyrightText: 2026 The Nikasha Authors
// SPDX-License-Identifier: Apache-2.0

// Go fixture: index out of range panic three calls deep.
package main

import "fmt"

func pick(values []int, i int) int {
	return values[i]
}

func last(values []int) int {
	return pick(values, len(values))
}

func main() {
	fmt.Println(last([]int{1, 2, 3}))
}
