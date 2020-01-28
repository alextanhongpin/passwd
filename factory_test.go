package passwd_test

import (
	"log"
	"testing"

	"github.com/alextanhongpin/passwd"
)

func ExampleNew() {
	hasher := passwd.New(
		passwd.Time(2),
		passwd.Memory(64*1024),
		passwd.Parallelism(4),
		passwd.SaltLen(32),
		passwd.KeyLen(100),
	)

	password := []byte("secret")
	hash, err := hasher.Encrypt(password)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(hash)

	match, err := hasher.Compare(hash, password)
	if err != nil {
		log.Fatal(err)
	}
	if match != true {
		log.Fatal("password do not match")
	}
}

func TestFactorySetup(t *testing.T) {
	password := []byte("hello world")

	hasher := passwd.New(passwd.Time(10))
	hash, err := hasher.Encrypt(password)
	if err != nil {
		t.Fatal(err)
	}
	match, err := hasher.Compare(hash, password)
	if err != nil {
		t.Fatal(err)
	}
	if match != true {
		t.Fatalf("expected %t, got %t", true, match)
	}
}
