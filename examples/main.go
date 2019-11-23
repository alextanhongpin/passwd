package main

import (
	"log"

	"github.com/alextanhongpin/passwd"
)

func main() {
	password := "your raw text password"
	hash, err := passwd.Encrypt(password)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(hash)

	match, err := passwd.Compare(password, hash)
	if err != nil {
		log.Fatal(err)
	}
	if match != true {
		log.Fatal("password do not match")
	}
}
