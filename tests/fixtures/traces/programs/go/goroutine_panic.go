// SPDX-FileCopyrightText: 2026 The Nikasha Authors
// SPDX-License-Identifier: Apache-2.0

// Go fixture: a panic inside a goroutine (run with GOTRACEBACK=all).
package main

import (
	"errors"
	"sync"
)

func validate(job int) error {
	if job == 3 {
		return errors.New("job 3 has no owner")
	}
	return nil
}

func worker(job int, wg *sync.WaitGroup) {
	defer wg.Done()
	if err := validate(job); err != nil {
		panic(err)
	}
}

func main() {
	var wg sync.WaitGroup
	for job := 1; job <= 3; job++ {
		wg.Add(1)
		go worker(job, &wg)
	}
	wg.Wait()
}
