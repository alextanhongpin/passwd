package main

import (
	"log"

	"github.com/alextanhongpin/passwd"
)

func main() {
	hasher := passwd.New(
		passwd.Time(2),
		passwd.Memory(64*1024),
		passwd.Parallelism(4),
		passwd.SaltLen(32),
		passwd.KeyLen(100),
	)

	password := "secret"
	hash, err := hasher.Encrypt(password)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(hash)

	match, err := hasher.Compare(password, hash)
	if err != nil {
		log.Fatal(err)
	}
	if match != true {
		log.Fatal("password do not match")
	}
}
