module rsa

import math.big
import crypto.rand

pub struct PublicKey {
pub:
	n big.Integer
	e big.Integer
}

pub fn (pk PublicKey) str() string {
	return 'PublicKey(e=0x${pk.e.hex()}, n=0x${pk.n.hex()})'
}

pub struct PrivateKey {
pub:
	p big.Integer
	q big.Integer
	d big.Integer
	n big.Integer
}

pub fn (pk PrivateKey) str() string {
	return 'PrivateKey(p=0x${pk.p.hex()}, q=0x${pk.q.hex()}, d=0x${pk.d.hex()}, q=0x${pk.n.hex()})'
}

pub struct KeyPair {
pub:
	pubkey   PublicKey
	privkey  PrivateKey
	key_size int
}

pub fn (kp KeyPair) str() string {
	return 'KeyPair(key_size=${kp.key_size}, pub=${kp.pubkey}, priv=${kp.privkey})'
}

fn powmod(a big.Integer, e big.Integer, n big.Integer) big.Integer {
	// faster than big.big_mod_pow
	mut x := a % n
	mut b := e
	mut r := big.one_int
	for b > big.zero_int {
		if b % big.two_int == big.one_int {
			r = (r * x) % n
		}
		x = (x * x) % n
		b = b.rshift(1)
	}
	return r
}

pub fn is_prime(x big.Integer) bool {
	// primarity test through Fermat's Little Theorem (FLT) using three rounds
	bases := [big.two_int, big.integer_from_int(3), big.integer_from_int(5)]
	p := x - big.one_int
	for a in bases {
		if powmod(a, p, x) != big.one_int {
			return false
		}
	}
	return true
}

pub fn get_prime(bitlen int) ?big.Integer {
	nbytes := (bitlen + 4) / 8
	six := big.integer_from_int(6)
	for {
		byte_array := rand.bytes(nbytes) or { return error('Error while generating random prime') }
		n := big.integer_from_bytes(byte_array)
		c := six * n - big.one_int
		if is_prime(c) {
			return c
		}
		d := six * n + big.one_int
		if is_prime(d) {
			return d
		}
	}
	return error("Can't get a prime number :/")
}

fn invmod(a big.Integer, m big.Integer) big.Integer {
	return if a < big.two_int { a } else { m - invmod(m % a, a) * m / a }
}

pub fn generate_keypair(key_size int) ?KeyPair {
	p := get_prime(key_size / 2) or { return error('Error generating primes') }
	mut q := get_prime(key_size / 2) or { return error('Error generating primes') }
	for p == q {
		q = get_prime(key_size / 2) or { return error('Error generating primes') }
	}

	pb := PublicKey{
		n: p * q
		e: big.integer_from_int(65537)
	}

	d := invmod(pb.e, (p - big.one_int) * (q - big.one_int))

	if d == big.zero_int {
		return error("Invmod doesn't exist!")
	}

	pv := PrivateKey{
		p: p
		q: q
		n: pb.n
		d: d
	}
	return KeyPair{
		pubkey: pb
		privkey: pv
		key_size: key_size
	}
}

// encrypt

pub fn (pk PublicKey) encrypt_integer(i big.Integer) big.Integer {
	return powmod(i, pk.e, pk.n)
}

pub fn (pk PublicKey) encrypt_bytes(bytes []u8) []u8 {
	b, _ := pk.encrypt_integer(big.integer_from_bytes(bytes)).bytes()
	return b
}

pub fn (pk PublicKey) encrypt_string(s string) []u8 {
	return pk.encrypt_bytes(s.bytes())
}

pub fn (kp KeyPair) encrypt_integer(i big.Integer) big.Integer {
	return kp.pubkey.encrypt_integer(i)
}

pub fn (kp KeyPair) encrypt_bytes(bytes []u8) []u8 {
	b, _ := kp.encrypt_integer(big.integer_from_bytes(bytes)).bytes()
	return b
}

pub fn (kp KeyPair) encrypt_string(s string) []u8 {
	return kp.pubkey.encrypt_bytes(s.bytes())
}

// decrypt

pub fn (pk PrivateKey) decrypt_integer(i big.Integer) big.Integer {
	return powmod(i, pk.d, pk.n)
}

pub fn (pk PrivateKey) decrypt_bytes(bytes []u8) []u8 {
	b, _ := pk.decrypt_integer(big.integer_from_bytes(bytes)).bytes()
	return b
}

pub fn (pk PrivateKey) decrypt_string(s string) []u8 {
	return pk.decrypt_bytes(s.bytes())
}

pub fn (kp KeyPair) decrypt_integer(i big.Integer) big.Integer {
	return kp.privkey.decrypt_integer(i)
}

pub fn (kp KeyPair) decrypt_bytes(bytes []u8) []u8 {
	b, _ := kp.decrypt_integer(big.integer_from_bytes(bytes)).bytes()
	return b
}

pub fn (kp KeyPair) decrypt_string(s string) []u8 {
	return kp.privkey.decrypt_bytes(s.bytes())
}
