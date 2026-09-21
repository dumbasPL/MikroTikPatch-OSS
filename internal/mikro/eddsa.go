package mikro

import "crypto/ed25519"

// EdDSASign signs data with an Ed25519 private key seed (32 bytes).  The
// vendored Python library produces standard RFC 8032 signatures, so the
// standard library is byte-for-byte compatible.
func EdDSASign(data, privateKey []byte) []byte {
	key := ed25519.NewKeyFromSeed(privateKey)
	return ed25519.Sign(key, data)
}

// EdDSAVerify verifies a standard Ed25519 signature.
func EdDSAVerify(data, signature, publicKey []byte) bool {
	if len(publicKey) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(publicKey), data, signature)
}

// EdDSAPublicFromSeed derives the 32-byte Ed25519 public key for a seed.
func EdDSAPublicFromSeed(privateKey []byte) []byte {
	key := ed25519.NewKeyFromSeed(privateKey)
	return key.Public().(ed25519.PublicKey)
}
