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

pub fn is_prime(x big.Integer) bool {
	// primarity test through Fermat's Little Theorem (FLT) using three rounds
	bases := [big.two_int, big.integer_from_int(3), big.integer_from_int(5),
		big.integer_from_int(191), big.integer_from_int(1583)]
	p := x - big.one_int
	for a in bases {
		if (a.big_mod_pow(p, x) or { big.zero_int }) != big.one_int {
			return false
		}
	}
	return true
}

// 110

pub fn get_prime(bitlen int) !big.Integer {
	low := big.two_int.pow(u32(bitlen - 1))
	top := big.two_int.pow(u32(bitlen))
	mut s := bitlen / 8
	for {
		n := low + big.two_int * big.integer_from_bytes(rand.bytes(s)!) + big.one_int
		if n < top && is_prime(n) {
			return n
		}
		// s = n.int() % bitlen
	}
	return error("Can't get a prime number :/")
}

fn invmod(a big.Integer, m big.Integer) big.Integer {
	return if a < big.two_int { a } else { m - invmod(m % a, a) * m / a }
}

pub fn generate_keypair(key_size int) !KeyPair {
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
	return i.big_mod_pow(pk.e, pk.n) or { big.zero_int }
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
	return i.big_mod_pow(pk.d, pk.n) or { big.zero_int }
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
