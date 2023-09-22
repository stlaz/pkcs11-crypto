package rand

import (
	"io"

	"github.com/stlaz/pkcs11-crypto/api"
)

type Reader struct {
	session *api.Session
}

var _ io.Reader = &Reader{}

func NewReader(p11session *api.Session) *Reader {
	return &Reader{
		session: p11session,
	}
}

func (r *Reader) Read(target []byte) (int, error) {
	var err error
	readLen := len(target)
	if target, err = r.session.GenerateRandom(r.session.SessionHandle, readLen); err != nil {
		return 0, err
	}
	return readLen, nil
}
