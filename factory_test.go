package passwd_test

import (
	"testing"

	"github.com/alextanhongpin/passwd"
)

func TestFactorySetup(t *testing.T) {
	password := "hello world"

	hasher := passwd.New(passwd.Time(10))
	hash, err := hasher.Hash(password)
	if err != nil {
		t.Fatal(err)
	}
	err = hasher.Verify(password, hash)
	if err != nil {
		t.Fatal(err)
	}
}
