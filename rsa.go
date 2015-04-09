package sshcrypt

import (
	"crypto/rsa"
	"errors"
	"math/big"

	"golang.org/x/crypto/ssh"
)

type rsaPublicKey rsa.PublicKey

func (r *rsaPublicKey) Type() string {
	return ssh.KeyAlgoRSA
}

func (r *rsaPublicKey) Marshal() []byte {
	e := new(big.Int).SetInt64(int64(r.E))
	wirekey := struct {
		Name string
		E    *big.Int
		N    *big.Int
	}{
		ssh.KeyAlgoRSA,
		e,
		r.N,
	}
	return ssh.Marshal(&wirekey)
}

// parseRSA parses an RSA key according to RFC 4253, section 6.6.
func parseRSA(in []byte) (out *rsaPublicKey, rest []byte, err error) {
	var w struct {
		E    *big.Int
		N    *big.Int
		Rest []byte `ssh:"rest"`
	}
	if err := ssh.Unmarshal(in, &w); err != nil {
		return nil, nil, err
	}

	if w.E.BitLen() > 24 {
		return nil, nil, errors.New("ssh: exponent too large")
	}
	e := w.E.Int64()
	if e < 3 || e&1 == 0 {
		return nil, nil, errors.New("ssh: incorrect exponent")
	}

	var key rsaPublicKey
	key.E = int(e)
	key.N = w.N
	return (*rsaPublicKey)(&key), w.Rest, nil
}

type rsaPrivateKey rsa.PrivateKey
