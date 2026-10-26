package main

import (
	"bytes"
	"io"
	"sort"
	"sync"
)

const minRedactLen = 4

type secret struct {
	value []byte
	mask  []byte
}

// redactor replaces secret values in a stream. It holds back only the tail
// that could still be the start of a secret, so normal output is not delayed.
type redactor struct {
	mu      sync.Mutex
	out     io.Writer
	secrets []secret
	buf     []byte
}

func newRedactor(out io.Writer, values map[string]string) *redactor {
	r := &redactor{out: out}
	for k, v := range values {
		if len(v) < minRedactLen {
			continue
		}
		r.secrets = append(r.secrets, secret{[]byte(v), []byte("***" + k + "***")})
	}
	// Longest first, so a secret that contains another is masked whole.
	sort.Slice(r.secrets, func(i, j int) bool { return len(r.secrets[i].value) > len(r.secrets[j].value) })
	return r
}

func (r *redactor) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf = append(r.buf, p...)
	for _, s := range r.secrets {
		r.buf = bytes.ReplaceAll(r.buf, s.value, s.mask)
	}
	hold := r.holdback()
	if _, err := r.out.Write(r.buf[:len(r.buf)-hold]); err != nil {
		return 0, err
	}
	r.buf = append(r.buf[:0], r.buf[len(r.buf)-hold:]...)
	return len(p), nil
}

func (r *redactor) holdback() int {
	best := 0
	for _, s := range r.secrets {
		max := len(s.value) - 1
		if max > len(r.buf) {
			max = len(r.buf)
		}
		for k := max; k > best; k-- {
			if bytes.HasPrefix(s.value, r.buf[len(r.buf)-k:]) {
				best = k
				break
			}
		}
	}
	return best
}

func (r *redactor) Flush() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, err := r.out.Write(r.buf)
	r.buf = r.buf[:0]
	return err
}
