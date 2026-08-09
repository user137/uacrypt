package dstu

// #include "dstu_core.h"
import "C"

// Fixed byte lengths mirroring the DSTU_* macros in dstu_core.h.
const (
	BoxSecretKeyBytes = int(C.DSTU_BOX_SECRETKEY_BYTES)
	BoxPublicKeyBytes = int(C.DSTU_BOX_PUBLICKEY_BYTES)
	// BoxSealOverhead is the 128-byte KEM ciphertext + 32-byte secretstream header + 16-byte tag
	// added by BoxPublicKey.Seal.
	BoxSealOverhead      = int(C.DSTU_BOX_SEAL_OVERHEAD)
	Box512SecretKeyBytes = int(C.DSTU_BOX512_SECRETKEY_BYTES)
	Box512PublicKeyBytes = int(C.DSTU_BOX512_PUBLICKEY_BYTES)
	// Box512SealOverhead is the 256-byte KEM ciphertext + 32-byte secretstream header + 16-byte
	// tag added by Box512PublicKey.Seal - the l(p)=512 sibling of BoxSealOverhead.
	Box512SealOverhead  = int(C.DSTU_BOX512_SEAL_OVERHEAD)
	AuthKeyBytes        = int(C.DSTU_AUTH_KEY_BYTES)
	AuthTagBytes        = int(C.DSTU_AUTH_TAG_BYTES)
	GenericHash256Bytes = int(C.DSTU_GENERICHASH_256_BYTES)
	GenericHash512Bytes = int(C.DSTU_GENERICHASH_512_BYTES)
	KdfKeyBytes         = int(C.DSTU_KDF_KEY_BYTES)
	KdfContextBytes     = int(C.DSTU_KDF_CONTEXT_BYTES)
	KdfSubkeyBytes      = int(C.DSTU_KDF_SUBKEY_BYTES)
	// PwhashStrBytes is the fixed buffer size for a PHC string produced by HashPassword.
	PwhashStrBytes    = int(C.DSTU_PWHASH_STRBYTES)
	SecretboxKeyBytes = int(C.DSTU_SECRETBOX_KEY_BYTES)
	// SecretboxOverhead is the 32-byte nonce + 16-byte tag added by Seal.
	SecretboxOverhead       = int(C.DSTU_SECRETBOX_OVERHEAD)
	SecretstreamKeyBytes    = int(C.DSTU_SECRETSTREAM_KEY_BYTES)
	SecretstreamHeaderBytes = int(C.DSTU_SECRETSTREAM_HEADER_BYTES)
	SecretstreamTagBytes    = int(C.DSTU_SECRETSTREAM_TAG_BYTES)
	SignPrivateKeyBytes     = int(C.DSTU_SIGN_PRIVATE_KEY_BYTES)
	SignPublicKeyBytes      = int(C.DSTU_SIGN_PUBLIC_KEY_BYTES)
	SignSignatureBytes      = int(C.DSTU_SIGN_SIGNATURE_BYTES)
	SignDigestBytes         = int(C.DSTU_SIGN_DIGEST_BYTES)
	Sign257PrivateKeyBytes  = int(C.DSTU_SIGN257_PRIVATE_KEY_BYTES)
	Sign257PublicKeyBytes   = int(C.DSTU_SIGN257_PUBLIC_KEY_BYTES)
	Sign257SignatureBytes   = int(C.DSTU_SIGN257_SIGNATURE_BYTES)
	Sign257DigestBytes      = int(C.DSTU_SIGN257_DIGEST_BYTES)
	StreamKeyBytes          = int(C.DSTU_STREAM_KEY_BYTES)
	// StreamOverhead is the 32-byte IV added by StreamCipherKey.Encrypt - no tag, unauthenticated.
	StreamOverhead = int(C.DSTU_STREAM_OVERHEAD)
)

// PwhashStrength is an Argon2id cost preset - mirrors DstuPwhashStrength in dstu_core.h and
// libsodium's own named OPSLIMIT/MEMLIMIT_* constants.
type PwhashStrength int

const (
	PwhashInteractive PwhashStrength = C.DSTU_PWHASH_INTERACTIVE
	PwhashModerate    PwhashStrength = C.DSTU_PWHASH_MODERATE
	PwhashSensitive   PwhashStrength = C.DSTU_PWHASH_SENSITIVE
)

// SecretstreamTag is a chunk's role in a secretstream - mirrors DstuTag in dstu_core.h.
type SecretstreamTag int

const (
	TagMessage SecretstreamTag = C.DSTU_TAG_MESSAGE
	TagPush    SecretstreamTag = C.DSTU_TAG_PUSH
	TagRekey   SecretstreamTag = C.DSTU_TAG_REKEY
	TagFinal   SecretstreamTag = C.DSTU_TAG_FINAL
)
