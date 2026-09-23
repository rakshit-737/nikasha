// SPDX-FileCopyrightText: 2026 The Nikasha Authors
// SPDX-License-Identifier: Apache-2.0
package ring

import "fmt"

type Buffer struct {
	data []byte
	head int
}

type Sizer interface {
	Size() int
}

func New(n int) *Buffer {
	return &Buffer{data: make([]byte, n)}
}

func (b *Buffer) Push(x byte) {
	b.data[b.head] = x
	b.head = wrap(b.head+1, len(b.data))
}

func (b Buffer) Size() int {
	return len(b.data)
}

func wrap(i, n int) int {
	if i >= n {
		return 0
	}
	return i
}

func Dump(b *Buffer) {
	show := func() { fmt.Println(b.Size()) }
	show()
}
