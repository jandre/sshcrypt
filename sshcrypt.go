package sshcrypt

type SshKeyPair interface {
	// get the type of the key
	func Type() string
}



func GetRSAKeys(privateKey string, sshPublicKey string) {}
func GetDSAKeys(privateKey string, sshPublicKey string) {}


