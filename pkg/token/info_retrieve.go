package token

import (
	"fmt"
	"log/slog"

	"github.com/miekg/pkcs11"
	"github.com/stlaz/pkcs11-crypto/api"
)

func ListAvailableSlots(ctx *pkcs11.Ctx) []uint {
	usableSlots, err := ctx.GetSlotList(true)
	if err != nil {
		slog.Error("failed to list slots: %v", err)
	}

	return usableSlots
}

func GetKeyByID(s *api.Session, keyType uint, keyID []byte) (objs []pkcs11.ObjectHandle, err error) {
	if err := s.FindObjectsInit(s.SessionHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		// pkcs11.NewAttribute(pkcs11.CKA_TOKEN, pkcs11.CK_TRUE),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, keyType),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
	}); err != nil {
		return nil, fmt.Errorf("failed to initialize search: %w", err)
	}
	defer func() {
		if finErr := s.FindObjectsFinal(s.SessionHandle); finErr != nil {
			if err != nil {
				// there was an error in the search already, don't mask it
				slog.Error("failed to finalize object search: %v", err)
			}
			err = fmt.Errorf("failed to finalize object search: %w", finErr)
		}
	}()

	objs, _, err = s.FindObjects(s.SessionHandle, 0)
	return objs, err
}
