package api

import "github.com/miekg/pkcs11"

func WrapSession(ctx *pkcs11.Ctx, session pkcs11.SessionHandle) *Session {
	return &Session{
		Ctx:           ctx,
		SessionHandle: session,
	}
}

type Session struct {
	*pkcs11.Ctx
	pkcs11.SessionHandle
}
