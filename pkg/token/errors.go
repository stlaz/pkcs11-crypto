package token

import (
	"errors"

	"github.com/miekg/pkcs11"
)

func IsInvalidSlotID(err error) bool {
	var p11err pkcs11.Error
	if !errors.As(err, &p11err) {
		return false
	}
	return p11err == pkcs11.CKR_SLOT_ID_INVALID
}
