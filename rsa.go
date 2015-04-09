package sshcrypt

import (
	"crypto/rsa"
	"errors"
	"math/big"

	"golang.org/x/crypto/ssh"
)

// MarshalAuthorizedKey serializes key for inclusion in an OpenSSH
// authorized_keys file. The return value ends with newline.
// func MarshalAuthorizedKey(key PublicKey) []byte {
// b := &bytes.Buffer{}
// b.WriteString(key.Type())
// b.WriteByte(' ')
// e := base64.NewEncoder(base64.StdEncoding, b)
// e.Write(key.Marshal())
// e.Close()
// b.WriteByte('\n')
// return b.Bytes()
// }

type rsaPublicKey rsa.PublicKey

func (r *rsaPublicKey) Type() string {
	return "ssh-rsa"
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
