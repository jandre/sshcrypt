package sshcrypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"testing"
)

const PUBLIC_KEY = `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDMMySNbx3e/W7n6MD6cd9RYpqgPERvJytYCVDP9aMd2YbQpypfAATPmE367XgR+yHHXKfw81DAkAd5PJe/O8ZV1Td52i6bbR9rGAD9PRF1Gv6YxUZYAKbFgfWzXgdSDlUfX/7POjmKr507V8/7YoC0VGvgq9+2gOqj+8FL5qWtc2LaiudHz/7/fqx8WEhfjmuxaQfifgN6P7u3i6wIIgGr/Sqzm1w+F5ks1SR/lwk2nUM6jM3353ImhTSfcgC2WlPUNvWI1Qj0t7rRShwsgUpO4Cd3WlhRDMDR6mzeSdZ0VeDVVbDMroM1hr+NxIYUL7T5wQGdJDCVi0UNFj5JibF/ testcomment@testhost`

const PRIVATE_KEY = `-----BEGIN RSA PRIVATE KEY-----
MIIEpgIBAAKCAQEAzDMkjW8d3v1u5+jA+nHfUWKaoDxEbycrWAlQz/WjHdmG0Kcq
XwAEz5hN+u14Efshx1yn8PNQwJAHeTyXvzvGVdU3edoum20faxgA/T0RdRr+mMVG
WACmxYH1s14HUg5VH1/+zzo5iq+dO1fP+2KAtFRr4KvftoDqo/vBS+alrXNi2orn
R8/+/36sfFhIX45rsWkH4n4Dej+7t4usCCIBq/0qs5tcPheZLNUkf5cJNp1DOozN
9+dyJoU0n3IAtlpT1Db1iNUI9Le60UocLIFKTuAnd1pYUQzA0eps3knWdFXg1VWw
zK6DNYa/jcSGFC+0+cEBnSQwlYtFDRY+SYmxfwIDAQABAoIBAQCNmBkMibRo38t7
vAW0pCl6Qal+2suJV9vSXANRcL7+/8tf+8qBvX2Yhb/s86WCsmUl3LYHenDQVg8Y
nk+LJ2PMOOES+Zu/4tcaZ7an4ySr02AfhwvUEf+SjR9WlSj2WUHlU6dZAsLLzCJ2
99kcM52TbcawL/4ciyApPXU3sGPJ9S8ruMIv1FhvURfmGGHR35Jyzdik6NwGo78j
hgnN8KWSOxipF830fLCj9BEJ14tUNu41SMcgXFdTnRBEEkIoi6lUKifQVhZms22O
+oMtke+AUhfG2HLw45MzXPB31OlDFIw4bVKPOfrtSm6G8ujlxjxoNb0fh8BJyAVi
rZm0CZGhAoGBAPOH4v15lia4gQLzfdK9OTPCWvkdg1mOVqu2kcsqUNIyKu5OgQhY
sbH+dZwhcTuXA0T+kkY7t2FuWcIi8CFTcgyjTaBDG4f37EOW/i5asDHKfg2sF4/J
f7WFZDsSd/lxrFOA4iIOEE0obnRTZ5jI18I7inFORmYGy/UayJb7zTR1AoGBANan
uCBgs0CbqYFLeKSruK2oEtZ9C2xXThdr3fmKXN8mtwWjXAo7uwE0EfH4YmNyv2g6
uPTKHcUkqj4LjnqIzEgA1BWaGdFndO/KGm8R2ZWy803odnEjWqMFaJY48MAOJOFf
kvmBAlYwCUmqWFS9kcGVktov9+iEppNUA1v9Br+jAoGBAIrZcUxAJKITFEuQdK7R
AGpIaAIdF6TaCQSCZYHGsKoHvH5++AbAOyBXCstoLd1h7pVJ6DBvH9FHT5nmva7i
muYlvb6gRHQzoNuwnV/kiQz6fQBinFR4+H2QfmNH1mu8qho6I7Ry/ExhvwhH/YsZ
CBtQQ1Dy5iSJv4QSL0gWbRt5AoGBAJRM37sO1AkJAnzfhYRPV5IykoE5dxDs6Hjp
/zwOSceqWbw9drNjPPnB3bwM3PzUJEWAfJQyp4qyoCOpnFAv/uKoH96kzr2L+pBI
Uyb1cBwqvEnRFzNnN5F1hSJ0SHCH1RcYDtTuOo0NNv18APba2b6i9ghkJ6SvMN6M
pp2BHI59AoGBAKT1PM654f329CP57KmkFW1B2fz0RTv44y/Hs7u3xsgHppQqEnc4
wh0jL94Dv+i00tvES4VBtPVrxTxvNGZkSpoDXUXR2hAD8Wbm/S3bdDBsjT2EGJN8
ufIFjyzc8EV4yGcgOug2hFovZom3CGrI9nDDz8KgThuKihhxfwGPNOQt
-----END RSA PRIVATE KEY-----
`

func TestParseAuthorizedKey(t *testing.T) {
	keyBytes := []byte(PUBLIC_KEY)
	result, comment, opts, rest, err := ParseAuthorizedKey(keyBytes)

	t.Log("result is", result, comment, opts, rest)
	if err != nil {
		t.Fatal(err)
	}
}

func TestParsePrivateKey(t *testing.T) {
	keyBytes := []byte(PRIVATE_KEY)

	result, err := ParsePrivateKey(keyBytes, "")

	t.Log("result is", result)
	if err != nil {
		t.Fatal(err)
	}

}

func TestEncryption(t *testing.T) {

	pub, _, _, _, err := ParseAuthorizedKey([]byte(PUBLIC_KEY))

	pk := pub.(*RSAPublicKey)
	pubKey := pk.GetCryptoPublicKey()

	if err != nil {
		t.Fatal(err)
	}
	privKey, err := ParsePrivateKey([]byte(PRIVATE_KEY), "")

	if err != nil {
		t.Fatal(err)
	}

	sha1 := sha1.New()

	msg := "hello, i'm encrypting a string wtih rsa"
	in := []byte(msg)

	ciphertext, err := rsa.EncryptOAEP(sha1, rand.Reader, pubKey, in, nil)

	if err != nil {
		t.Fatal("Failed to encrypt message %v", err)
	}

	priv := rsa.PrivateKey(*privKey.(*RSAPrivateKey))

	decrypted, err := rsa.DecryptOAEP(sha1, rand.Reader, &priv, ciphertext, nil)

	if err != nil {
		t.Fatal("Failed to decrypt message %v", err)
	}

	// t.Log("Decrypted is", string(decrypted))

	if string(decrypted) != msg {
		t.Fatal("does not match:", string(decrypted), msg)
	}

}

func TestEncryptionHelpers(t *testing.T) {

	pub, _, _, _, err := ParseAuthorizedKey([]byte(PUBLIC_KEY))
	if err != nil {
		t.Fatal(err)
	}

	pk := pub.(*RSAPublicKey)

	privKey, err := ParsePrivateKey([]byte(PRIVATE_KEY), "")

	if err != nil {
		t.Fatal(err)
	}

	msg := "hello, i'm encrypting a string wtih rsa"
	in := []byte(msg)

	ciphertext, err := pk.EncryptBytes(in)

	if err != nil {
		t.Fatal("Failed to encrypt message %v", err)
	}

	priv := privKey.(*RSAPrivateKey)

	decrypted, err := priv.DecryptBytes(ciphertext)

	if err != nil {
		t.Fatal("Failed to decrypt message %v", err)
	}

	if string(decrypted) != msg {
		t.Fatal("does not match:", string(decrypted), msg)
	}

}
