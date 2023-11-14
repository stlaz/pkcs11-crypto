package keys

import (
	"crypto"
	"fmt"

	"github.com/miekg/pkcs11"
	"github.com/stlaz/pkcs11-crypto/api"
)

var _ crypto.PrivateKey = &RSAKey{}

// FIXME: implement
type RSAKey struct {
	key pkcs11.ObjectHandle
	pub pkcs11.ObjectHandle
}

func newRSAKey(key, pub pkcs11.ObjectHandle) *RSAKey {
	return &RSAKey{key: key, pub: pub}
}

func (k *RSAKey) Public() crypto.PublicKey {
	return nil
}

func (k *RSAKey) Equal(x crypto.PrivateKey) bool {
	return false
}

func (k *RSAKey) Destroy(p11ctx *pkcs11.Ctx, p11session pkcs11.SessionHandle) error {
	keyErr := p11ctx.DestroyObject(p11session, k.key)
	pubErr := p11ctx.DestroyObject(p11session, k.pub)

	if keyErr != nil {
		return fmt.Errorf("failed to destroy private key: %w", keyErr)
	}

	if pubErr != nil {
		return fmt.Errorf("failed to destroy public key: %w", pubErr)
	}

	return nil
}

func GenerateRSAKey(session *api.Session, keyID byte, bits uint) (*RSAKey, error) {
	pub, private, err := session.Ctx.GenerateKeyPair(session.SessionHandle,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)},
		[]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, pkcs11.CK_TRUE),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, pkcs11.CK_TRUE),
			pkcs11.NewAttribute(pkcs11.CKA_ID, []byte{keyID}),
			// pkcs11.NewAttribute(pkcs11.CKA_WRAP, pkcs11.CK_TRUE),
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, bits),
		},
		[]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_ID, []byte{keyID}),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, pkcs11.CK_TRUE),
			pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, pkcs11.CK_TRUE),
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, pkcs11.CK_TRUE),
			pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, pkcs11.CK_TRUE),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, pkcs11.CK_TRUE),
			// pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, pkcs11.CK_TRUE),
		},
	)
	if err != nil {
		return nil, err
	}

	return newRSAKey(private, pub), nil
}
