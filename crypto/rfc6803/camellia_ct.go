package rfc6803

// Camellia's F-function in constant time: no table lookups, no branches on
// the key or the data.
//
// Camellia's s1 is affine-equivalent to the AES S-box: s1(x) =
// A2(S_aes(A1(x))), with A1 and A2 affine maps over GF(2)^8 (found by a
// linear-equivalence search and checked on all 256 inputs against RFC 3713's
// SBOX1, see camellia_ct_test.go). So F's eight S-boxes run as Boyar and
// Peralta's bitsliced AES S-box circuit (113 gates of XOR, XNOR and AND) on
// eight bit planes, a byte of the input in each lane. s2 = s1 <<< 1,
// s3 = s1 <<< 7 and s4(x) = s1(x <<< 1) rotate the bits of their lanes,
// which on planes is a masked swap between neighbouring planes. The rest of
// Camellia is XORs, ANDs, ORs and fixed rotations.

// transpose8 transposes the 8x8 bit matrix x (byte r its row r, bit c its
// column c): byte j of the result holds bit j of every byte of x.
func transpose8(x uint64) uint64 {
	t := (x ^ (x >> 7)) & 0x00AA00AA00AA00AA
	x = x ^ t ^ (t << 7)
	t = (x ^ (x >> 14)) & 0x0000CCCC0000CCCC
	x = x ^ t ^ (t << 14)
	t = (x ^ (x >> 28)) & 0x00000000F0F0F0F0
	x = x ^ t ^ (t << 28)

	return x
}

// rotUp: in the lanes of m, bit j takes bit j-1 (mod 8): those bytes
// rotated left by one.
func rotUp(m uint32, p0, p1, p2, p3, p4, p5, p6, p7 uint32) (uint32, uint32, uint32, uint32, uint32, uint32, uint32, uint32) {
	return p0&^m | p7&m, p1&^m | p0&m, p2&^m | p1&m, p3&^m | p2&m,
		p4&^m | p3&m, p5&^m | p4&m, p6&^m | p5&m, p7&^m | p6&m
}

// rotDown: in the lanes of m, bit j takes bit j+1 (mod 8): those bytes
// rotated right by one.
func rotDown(m uint32, p0, p1, p2, p3, p4, p5, p6, p7 uint32) (uint32, uint32, uint32, uint32, uint32, uint32, uint32, uint32) {
	return p0&^m | p1&m, p1&^m | p2&m, p2&^m | p3&m, p3&^m | p4&m,
		p4&^m | p5&m, p5&^m | p6&m, p6&^m | p7&m, p7&^m | p0&m
}

// a1 is A1(x) = L1(x) ^ 0x08, on planes (p0 the low bit).
func a1(p0, p1, p2, p3, p4, p5, p6, p7 uint32) (uint32, uint32, uint32, uint32, uint32, uint32, uint32, uint32) {
	return p0 ^ p1 ^ p2 ^ p3 ^ p4 ^ p5 ^ p6 ^ p7,
		p3 ^ p4 ^ p5,
		p4,
		^(p1 ^ p3 ^ p7),
		p1 ^ p2 ^ p5 ^ p7,
		p2 ^ p3 ^ p4 ^ p6,
		p6 ^ p7,
		p2 ^ p3 ^ p4 ^ p5 ^ p7
}

// a2 is A2(x) = L2(x) ^ 0x11.
func a2(p0, p1, p2, p3, p4, p5, p6, p7 uint32) (uint32, uint32, uint32, uint32, uint32, uint32, uint32, uint32) {
	return ^(p0 ^ p1 ^ p2 ^ p5),
		p0 ^ p2,
		p1 ^ p2,
		p2 ^ p4 ^ p5 ^ p7,
		^(p0 ^ p1 ^ p4 ^ p5),
		p2 ^ p3 ^ p4 ^ p6 ^ p7,
		p3 ^ p5,
		p0 ^ p1 ^ p4 ^ p5 ^ p6 ^ p7
}

// aesSbox is the AES S-box on bit planes (q0 the low bit, q7 the high),
// Boyar and Peralta's circuit ("A depth-16 circuit for the AES S-box", 2011)
// as BearSSL orders it.
func aesSbox(q0, q1, q2, q3, q4, q5, q6, q7 uint32) (uint32, uint32, uint32, uint32, uint32, uint32, uint32, uint32) {
	x0, x1, x2, x3 := q7, q6, q5, q4
	x4, x5, x6, x7 := q3, q2, q1, q0

	// Top linear transformation.
	y14 := x3 ^ x5
	y13 := x0 ^ x6
	y9 := x0 ^ x3
	y8 := x0 ^ x5
	t0 := x1 ^ x2
	y1 := t0 ^ x7
	y4 := y1 ^ x3
	y12 := y13 ^ y14
	y2 := y1 ^ x0
	y5 := y1 ^ x6
	y3 := y5 ^ y8
	t1 := x4 ^ y12
	y15 := t1 ^ x5
	y20 := t1 ^ x1
	y6 := y15 ^ x7
	y10 := y15 ^ t0
	y11 := y20 ^ y9
	y7 := x7 ^ y11
	y17 := y10 ^ y11
	y19 := y10 ^ y8
	y16 := t0 ^ y11
	y21 := y13 ^ y16
	y18 := x0 ^ y16

	// Non-linear section.
	t2 := y12 & y15
	t3 := y3 & y6
	t4 := t3 ^ t2
	t5 := y4 & x7
	t6 := t5 ^ t2
	t7 := y13 & y16
	t8 := y5 & y1
	t9 := t8 ^ t7
	t10 := y2 & y7
	t11 := t10 ^ t7
	t12 := y9 & y11
	t13 := y14 & y17
	t14 := t13 ^ t12
	t15 := y8 & y10
	t16 := t15 ^ t12
	t17 := t4 ^ t14
	t18 := t6 ^ t16
	t19 := t9 ^ t14
	t20 := t11 ^ t16
	t21 := t17 ^ y20
	t22 := t18 ^ y19
	t23 := t19 ^ y21
	t24 := t20 ^ y18

	t25 := t21 ^ t22
	t26 := t21 & t23
	t27 := t24 ^ t26
	t28 := t25 & t27
	t29 := t28 ^ t22
	t30 := t23 ^ t24
	t31 := t22 ^ t26
	t32 := t31 & t30
	t33 := t32 ^ t24
	t34 := t23 ^ t33
	t35 := t27 ^ t33
	t36 := t24 & t35
	t37 := t36 ^ t34
	t38 := t27 ^ t36
	t39 := t29 & t38
	t40 := t25 ^ t39

	t41 := t40 ^ t37
	t42 := t29 ^ t33
	t43 := t29 ^ t40
	t44 := t33 ^ t37
	t45 := t42 ^ t41
	z0 := t44 & y15
	z1 := t37 & y6
	z2 := t33 & x7
	z3 := t43 & y16
	z4 := t40 & y1
	z5 := t29 & y7
	z6 := t42 & y11
	z7 := t45 & y17
	z8 := t41 & y10
	z9 := t44 & y12
	z10 := t37 & y3
	z11 := t33 & y4
	z12 := t43 & y13
	z13 := t40 & y5
	z14 := t29 & y2
	z15 := t42 & y9
	z16 := t45 & y14
	z17 := t41 & y8

	// Bottom linear transformation.
	t46 := z15 ^ z16
	t47 := z10 ^ z11
	t48 := z5 ^ z13
	t49 := z9 ^ z10
	t50 := z2 ^ z12
	t51 := z2 ^ z5
	t52 := z7 ^ z8
	t53 := z0 ^ z3
	t54 := z6 ^ z7
	t55 := z16 ^ z17
	t56 := z12 ^ t48
	t57 := t50 ^ t53
	t58 := z4 ^ t46
	t59 := z3 ^ t54
	t60 := t46 ^ t57
	t61 := z14 ^ t57
	t62 := t52 ^ t58
	t63 := t49 ^ t58
	t64 := z4 ^ t59
	t65 := t61 ^ t62
	t66 := z1 ^ t63
	s0 := t59 ^ t63
	s6 := t56 ^ ^t62
	s7 := t48 ^ ^t60
	t67 := t64 ^ t65
	s3 := t53 ^ t66
	s4 := t51 ^ t66
	s5 := t47 ^ t65
	s1 := t64 ^ ^s3
	s2 := t55 ^ ^t67

	return s7, s6, s5, s4, s3, s2, s1, s0
}

// The lanes are bytes from the low end: t8 is lane 0, t1 lane 7. F takes
// t1..t8 through s1 s2 s3 s4 s2 s3 s4 s1.
const (
	lanesS2 = 0x48 // t2, t5
	lanesS3 = 0x24 // t3, t6
	lanesS4 = 0x12 // t4, t7
)

// sboxes applies F's S-boxes to the eight bytes of x: s1 to the first and
// last, s2, s3, s4 to the second to fourth and again to the fifth to
// seventh (RFC 3713 2.4.1).
func sboxes(x uint64) uint64 {
	x = transpose8(x)

	q0, q1, q2, q3 := uint32(x)&0xff, uint32(x>>8)&0xff, uint32(x>>16)&0xff, uint32(x>>24)&0xff
	q4, q5, q6, q7 := uint32(x>>32)&0xff, uint32(x>>40)&0xff, uint32(x>>48)&0xff, uint32(x>>56)

	q0, q1, q2, q3, q4, q5, q6, q7 = rotUp(lanesS4, q0, q1, q2, q3, q4, q5, q6, q7)
	q0, q1, q2, q3, q4, q5, q6, q7 = a1(q0, q1, q2, q3, q4, q5, q6, q7)
	q0, q1, q2, q3, q4, q5, q6, q7 = aesSbox(q0, q1, q2, q3, q4, q5, q6, q7)
	q0, q1, q2, q3, q4, q5, q6, q7 = a2(q0, q1, q2, q3, q4, q5, q6, q7)
	q0, q1, q2, q3, q4, q5, q6, q7 = rotUp(lanesS2, q0, q1, q2, q3, q4, q5, q6, q7)
	q0, q1, q2, q3, q4, q5, q6, q7 = rotDown(lanesS3, q0, q1, q2, q3, q4, q5, q6, q7)

	y := uint64(q0&0xff) | uint64(q1&0xff)<<8 | uint64(q2&0xff)<<16 | uint64(q3&0xff)<<24 |
		uint64(q4&0xff)<<32 | uint64(q5&0xff)<<40 | uint64(q6&0xff)<<48 | uint64(q7&0xff)<<56

	return transpose8(y)
}

// fFunc is Camellia's F-function (RFC 3713 2.4.1): the S-boxes, then the
// P-function.
func fFunc(input, ke uint64) uint64 {
	t := sboxes(input ^ ke)

	t1, t2, t3, t4 := byte(t>>56), byte(t>>48), byte(t>>40), byte(t>>32)
	t5, t6, t7, t8 := byte(t>>24), byte(t>>16), byte(t>>8), byte(t)

	y1 := t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8
	y2 := t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8
	y3 := t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8
	y4 := t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7
	y5 := t1 ^ t2 ^ t6 ^ t7 ^ t8
	y6 := t2 ^ t3 ^ t5 ^ t7 ^ t8
	y7 := t3 ^ t4 ^ t5 ^ t6 ^ t8
	y8 := t1 ^ t4 ^ t5 ^ t6 ^ t7

	return uint64(y1)<<56 | uint64(y2)<<48 | uint64(y3)<<40 | uint64(y4)<<32 |
		uint64(y5)<<24 | uint64(y6)<<16 | uint64(y7)<<8 | uint64(y8)
}
