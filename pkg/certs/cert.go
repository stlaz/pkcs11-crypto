package certs

import "github.com/miekg/pkcs11"

// see https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/csd03/pkcs11-base-v2.40-csd03.html
// 4.4 storage objects
// 4.6 certificate objects
// 4.6.3 public key x509 certificate objects
// for available attributes
// FIXME: very much unused right now
func certTemplate(label, subject, issuer string) []*pkcs11.Attribute {
	// FIXME: DER-encode subject and issuer

	// FIXME: cannot generate certs until we have a signer
	return []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKC_X_509),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, pkcs11.CK_TRUE), // it's a token object, not a session object
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, subject),
		pkcs11.NewAttribute(pkcs11.CKA_ISSUER, issuer),
	}
}
