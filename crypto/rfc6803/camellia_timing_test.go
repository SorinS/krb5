package rfc6803

import (
	"crypto/rand"
	"encoding/binary"
	"math"
	"os"
	"strconv"
	"testing"
	"time"
)

// dudect (Reparaz, Balasch, Verbauwhede, "Dude, is my code constant
// time?", 2017): the time of F over a fixed input against random ones,
// interleaved at random; Welch's t over the measurements (the slowest 10%
// cropped). |t| above 4.5 says the time depends on the data. The table F
// this package had is measured the same way, for comparison. Slow: run with
// CAMELLIA_TIMING=1 (CAMELLIA_TIMING_N measurements, 2000000 by default).
func TestCamelliaTiming(t *testing.T) {
	if os.Getenv("CAMELLIA_TIMING") != "1" {
		t.Skip("set CAMELLIA_TIMING=1 to run")
	}

	n := 2000000
	if v, err := strconv.Atoi(os.Getenv("CAMELLIA_TIMING_N")); err == nil {
		n = v
	}

	for _, c := range []struct {
		name string
		f    func(uint64, uint64) uint64
	}{{"constant-time F", fFunc}, {"table F", fFuncTable}} {
		tv := dudect(n, c.f)
		t.Logf("%s: t = %.2f over %d measurements", c.name, tv, n)

		if c.name == "constant-time F" && math.Abs(tv) > 4.5 {
			t.Errorf("%s: |t| = %.2f > 4.5", c.name, math.Abs(tv))
		}
	}
}

var sink uint64

func dudect(n int, f func(uint64, uint64) uint64) float64 {
	const batch = 32

	r := make([]byte, n*8+n)
	_, _ = rand.Read(r)

	key := uint64(0x0123456789abcdef)

	// The inputs, made before anything is timed: the fixed one or a random
	// one, the timed code the same for both.
	classes := make([]int, n)
	inputs := make([]uint64, n)

	for i := 0; i < n; i++ {
		classes[i] = int(r[n*8+i] & 1)
		if classes[i] == 1 {
			inputs[i] = binary.LittleEndian.Uint64(r[i*8:])
		}
	}

	var times [2][]float64

	for i := 0; i < n; i++ {
		x := inputs[i]
		acc := uint64(0)

		start := time.Now()
		for j := 0; j < batch; j++ {
			acc ^= f(x, key)
		}
		d := time.Since(start)

		times[classes[i]] = append(times[classes[i]], float64(d))
		sink ^= acc
	}

	return welch(crop(times[0]), crop(times[1]))
}

// crop drops the slowest 10% (interrupts, preemption).
func crop(v []float64) []float64 {
	sorted := append([]float64(nil), v...)
	quickSort(sorted)
	limit := sorted[len(sorted)*9/10]

	var out []float64
	for _, x := range v {
		if x <= limit {
			out = append(out, x)
		}
	}

	return out
}

func quickSort(a []float64) {
	if len(a) < 2 {
		return
	}

	p := a[len(a)/2]
	i, j := 0, len(a)-1

	for i <= j {
		for a[i] < p {
			i++
		}

		for a[j] > p {
			j--
		}

		if i <= j {
			a[i], a[j] = a[j], a[i]
			i++
			j--
		}
	}

	quickSort(a[:j+1])
	quickSort(a[i:])
}

func welch(a, b []float64) float64 {
	mean := func(v []float64) float64 {
		s := 0.0
		for _, x := range v {
			s += x
		}

		return s / float64(len(v))
	}
	variance := func(v []float64, m float64) float64 {
		s := 0.0
		for _, x := range v {
			s += (x - m) * (x - m)
		}

		return s / float64(len(v)-1)
	}

	ma, mb := mean(a), mean(b)
	va, vb := variance(a, ma), variance(b, mb)

	return (ma - mb) / math.Sqrt(va/float64(len(a))+vb/float64(len(b)))
}
