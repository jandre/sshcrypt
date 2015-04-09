package sshcrypt

import "testing"

const PUBLIC_KEY = `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDMMySNbx3e/W7n6MD6cd9RYpqgPERvJytYCVDP9aMd2YbQpypfAATPmE367XgR+yHHXKfw81DAkAd5PJe/O8ZV1Td52i6bbR9rGAD9PRF1Gv6YxUZYAKbFgfWzXgdSDlUfX/7POjmKr507V8/7YoC0VGvgq9+2gOqj+8FL5qWtc2LaiudHz/7/fqx8WEhfjmuxaQfifgN6P7u3i6wIIgGr/Sqzm1w+F5ks1SR/lwk2nUM6jM3353ImhTSfcgC2WlPUNvWI1Qj0t7rRShwsgUpO4Cd3WlhRDMDR6mzeSdZ0VeDVVbDMroM1hr+NxIYUL7T5wQGdJDCVi0UNFj5JibF/ testcomment@testhost`

func TestParseAuthorizedKey(t *testing.T) {
	keyBytes := []byte(PUBLIC_KEY)
	result, comment, opts, rest, err := ParseAuthorizedKey(keyBytes)

	t.Log("result is", result, comment, opts, rest)
	if err != nil {
		t.Fatal(err)
	}
}
