package passwd_test

import (
	"bytes"
	"fmt"
	"log"
	"testing"

	"github.com/alextanhongpin/passwd"
	"golang.org/x/text/unicode/norm"

	"github.com/stretchr/testify/assert"
)

func ExampleEncrypt() {
	password := "your raw text password"
	hash, err := passwd.Encrypt(password)
	if err != nil {
		panic(err)
	}
	log.Println(hash)
}

func ExampleCompare() {
	hash := "$argon2id$v=19$m=65536,t=2,p=4$Sw8vppzw93YpLPotOuQhAA==$1uIAcD43cWZB5AxXI+zMUx6e2zzMaAJL2F1rAF0MX88="
	password := "secret"
	err := passwd.Compare(hash, password)
	fmt.Println(err)
	// Output:
	// <nil>
}

func ExampleEncryptAndCompare() {
	password := "your raw text password"
	hash, err := passwd.Encrypt(password)
	fmt.Println(err)

	err = passwd.Compare(hash, password)
	fmt.Println(err)

	err = passwd.Compare(hash, "wrong password")
	fmt.Println(err)
	// Output:
	// <nil>
	// <nil>
	// passwd: wrong password
}

func TestPasswordHashAndCompare(t *testing.T) {
	is := assert.New(t)

	password := "secret"
	hash, err := passwd.Encrypt(password)
	is.Nil(err)
	is.Nil(passwd.Compare(hash, password))

	t.Log(hash)
}

func TestCompare(t *testing.T) {
	test := func(name string, phc, password string, err error) {
		t.Run(name, func(t *testing.T) {
			is := assert.New(t)
			is.ErrorIs(passwd.Compare(phc, password), err)
		})
	}
	test("empty phc", "", "x", passwd.ErrInvalidHash)
	test("empty password", "x", "", passwd.ErrEmptyPassword)
	test("invalid hash", "x", "x", passwd.ErrInvalidHash)
}

func TestNormalization(t *testing.T) {
	// latin small letter e with acute (1234567\u00e9)
	password1 := "1234567é"

	// latin small letter e followed by combining acute accent (1234567\u0065\u0301)
	password2 := "1234567é"

	t.Run("equality before normalization", func(t *testing.T) {
		is := assert.New(t)
		is.False(password1 == password2)
	})

	t.Run("equality after normalization", func(t *testing.T) {
		nfkc1 := norm.NFKC.Bytes([]byte(password1))
		nfkc2 := norm.NFKC.Bytes([]byte(password2))

		is := assert.New(t)
		is.True(bytes.Equal(nfkc1, nfkc2))
	})

	t.Run("normalized encryption", func(t *testing.T) {
		hash, err := passwd.Encrypt(password1)
		is := assert.New(t)
		is.Nil(err)

		is.Nil(passwd.Compare(hash, password2))
	})
}

func TestNormalizationLength(t *testing.T) {
	b := []byte("1234567é")
	nfc := norm.NFC.Bytes(b)
	nfd := norm.NFD.Bytes(b)
	nfkc := norm.NFKC.Bytes(b)
	nfkd := norm.NFKD.Bytes(b)

	is := assert.New(t)
	is.Equal(len(nfc), 9)
	is.Equal(len(nfd), 10)
	is.Equal(len(nfkc), 9)
	is.Equal(len(nfkd), 10)

	runelen := func(b []byte) int {
		// Using `len([]rune(string(b)))` is now as optimized as using `utf8.RuneCountInString(string(b))`
		//
		// Reference:
		// https://stackoverflow.com/questions/12668681/how-to-get-the-number-of-characters-in-a-string
		return len([]rune(string(b)))
	}

	is.Equal(runelen(nfc), 8)
	is.Equal(runelen(nfd), 9)
	is.Equal(runelen(nfkc), 8)
	is.Equal(runelen(nfkd), 9)
}
