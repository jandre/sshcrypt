package sshcrypt

import (
	"crypto/rsa"
	"errors"
	"math/big"

	"golang.org/x/crypto/ssh"
)

type RsaPublicKey rsa.PublicKey

func (r *RsaPublicKey) Type() string {
	return ssh.KeyAlgoRSA
}

func (r *RsaPublicKey) Marshal() []byte {
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
func parseRSA(in []byte) (out *RsaPublicKey, rest []byte, err error) {
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

	var key RsaPublicKey
	key.E = int(e)
	key.N = w.N
	return (*RsaPublicKey)(&key), w.Rest, nil
}

type rsaPrivateKey rsa.PrivateKey
