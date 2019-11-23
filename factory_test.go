package passwd_test

import (
	"testing"

	"github.com/alextanhongpin/passwd"
)

func TestFactorySetup(t *testing.T) {
	password := "hello world"

	hasher := passwd.New(passwd.Time(10))
	hash, err := hasher.Encrypt(password)
	if err != nil {
		t.Fatal(err)
	}
	match, err := hasher.Compare(password, hash)
	if err != nil {
		t.Fatal(err)
	}
	if match != true {
		t.Fatalf("expected %t, got %t", true, match)
	}
}
