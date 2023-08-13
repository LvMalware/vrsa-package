module oeap

import rsa { KeyPair }
import net.conv
import crypto.rand
import crypto.sha1
import crypto.internal.subtle

// Mask Generation Function
interface MGF {
	hlen int
	hash fn ([]u8) []u8
	mask([]u8, int) ![]u8
}

pub struct MGF1 {
	hlen int = sha1.size
	hash fn ([]u8) []u8 = sha1.sum
}

// MGF1 as presented in https://en.wikipedia.org/wiki/Mask_generation_function#MGF1
[direct_array_access]
pub fn (m MGF1) mask(z []u8, l int) ![]u8 {
	if l > usize(m.hlen) << 32 {
		return error('Mask is too long')
	}
	mut t := []u8{}
	mut seed := z.clone()
	seed << [u8(0x00), 0x00, 0x00, 0x00]
	mut counter := u32(0)
	for t.len < l {
		c := conv.hton32(counter)
		seed[z.len + 0] = u8((c >> 0x18) & 0xff)
		seed[z.len + 1] = u8((c >> 0x12) & 0xff)
		seed[z.len + 2] = u8((c >> 0x08) & 0xff)
		seed[z.len + 3] = u8((c >> 0x00) & 0xff)
		t << m.hash(seed)
		counter += 1
	}
	t.trim(l)
	return t
}

// OEAP as presented in RFC 8017
pub struct OEAP {
	mgf  MGF = MGF1{}
	hlen int = sha1.size
	hash fn ([]u8) []u8 = sha1.sum
mut:
	keypair KeyPair
}

// Create and return a new OEAP structure with the specified parameters
pub fn oeap_new(mgf MGF, hash fn ([]u8) []u8, hlen int, keypair KeyPair) &OEAP {
	mut o := &OEAP{
		mgf: mgf
		hlen: hlen
		hash: hash
		keypair: keypair
	}
	return o
}

[direct_array_access; inline]
fn xor(a []u8, b []u8) []u8 {
	assert a.len == b.len, 'Length mismatch'
	mut x := []u8{len: a.len}
	for i in 0 .. a.len {
		x[i] = a[i] ^ b[i]
	}
	return x
}

// Encrypts a message m with label l and returns an u8 array with the ciphertext.
// The label can be an empty array. See RFC 8017 for an explanation of what this label is.
// Note: There are some limitations on the size of the message that can be encrypted using this scheme
// specifically, the maximum size of a message is k - 2 * hlen - 2, where k is the number of bits in the RSA
// key and hlen is the number of bits in the output of the chosen hash function
pub fn (o &OEAP) encrypt(m []u8, l []u8) ![]u8 {
	if l.len > (1 << o.hlen) {
		return error('Label is too long')
	}
	k := (o.keypair.key_size / 8)
	if m.len > k - 2 * o.hlen - 2 {
		return error('Message is too long')
	}
	mut db := o.hash(l)
	db << []u8{len: k - m.len - 2 * o.hlen - 2, init: 0}
	db << u8(0x01)
	db << m
	seed := rand.bytes(o.hlen)!
	mask := o.mgf.mask(seed, k - o.hlen - 1)!
	masked_db := xor(db, mask)
	seed_mask := o.mgf.mask(masked_db, o.hlen)!
	masked_seed := xor(seed, seed_mask)
	mut em := [u8(0)]
	em << masked_seed
	em << masked_db
	enc := o.keypair.encrypt_bytes(em)
	return enc
}

// Decrypts a ciphertext c with label l and returns an u8 array with the plaintext
pub fn (o &OEAP) decrypt(c []u8, l []u8) ![]u8 {
	if l.len > (1 << o.hlen) {
		return error('Decryption error')
	}
	k := (o.keypair.key_size / 8)
	if c.len != k || k < 2 * o.hlen + 2 {
		return error('Decryption error')
	}
	mut em := o.keypair.decrypt_bytes(c)
	// ensure em has k bytes
	if em.len < k {
		em.prepend([]u8{len: k - em.len, init: 0})
	}
	// fail if the first byte is non-zero
	if em[0] != 0 {
		return error('Decryption error')
	}

	// drop the first (null) byte
	em.drop(1)

	lhash := o.hash(l)
	masked_db := em[o.hlen..]
	masked_seed := em[..o.hlen]
	smask := o.mgf.mask(masked_db, o.hlen) or { return error('Decryption error') }
	seed := xor(smask, masked_seed)
	dbmask := o.mgf.mask(seed, k - o.hlen - 1) or { return error('Decryption error') }
	db := xor(masked_db, dbmask)
	// Avoid timing attacks using constant time comparission
	if subtle.constant_time_compare(lhash, db[..o.hlen]) != 1 {
		return error('Decryption error')
	}
	mut index := 0
	for i in o.hlen .. db.len {
		if db[i] == 0x01 {
			index = i + 1
			// a 'break' here would leak information about the padding length
		}
	}

	if index == 0 {
		return error('Decryption error')
	}
	return db[index..].clone()
}
