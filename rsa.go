package sshcrypt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"

	"golang.org/x/crypto/ssh"
)

type RSAPublicKey rsa.PublicKey

func (r *RSAPublicKey) GetSshPublicKey() *ssh.PublicKey {
	var orig interface{} = r
	pk := orig.(ssh.PublicKey)
	return &pk
}

func (r *RSAPublicKey) GetCryptoPublicKey() *rsa.PublicKey {
	pk := rsa.PublicKey(*r)
	return &pk
}

func (pk *RSAPublicKey) toPEM() (string, error) {
	key, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		return "", err
	}
	block := pem.Block{Type: "BEGIN PUBLIC KEY", Bytes: key}
	return string(pem.EncodeToMemory(&block)), nil
}

func (r *RSAPublicKey) Type() string {
	return ssh.KeyAlgoRSA
}

func (r *RSAPublicKey) Verify(data []byte, sig *ssh.Signature) error {
	return errors.New("not implemented")
}

func (r *RSAPublicKey) Marshal() []byte {
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
func parseRSA(in []byte) (out *RSAPublicKey, rest []byte, err error) {
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

	var key RSAPublicKey
	key.E = int(e)
	key.N = w.N
	return (*RSAPublicKey)(&key), w.Rest, nil
}

func parseRSAPrivateKey(block *pem.Block, passphrase string) (*rsa.PrivateKey, error) {
	var privateBytes []byte
	var err error

	if passphrase != "" {
		privateBytes, err = x509.DecryptPEMBlock(block, []byte(passphrase))

		if err != nil {
			return nil, err
		}
	} else {
		privateBytes = block.Bytes
	}

	return x509.ParsePKCS1PrivateKey(privateBytes)
}
