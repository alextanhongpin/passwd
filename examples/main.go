package main

import (
	"log"

	"github.com/alextanhongpin/passwd"
)

func main() {
	password := "your raw text password"
	hash, err := passwd.Hash(password)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(hash)

	err = passwd.Verify(password, hash)
	if err != nil {
		log.Fatal(err)
	}
}
