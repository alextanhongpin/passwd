package passwd_test

import (
	"log"
	"testing"

	"github.com/alextanhongpin/passwd"

	"github.com/stretchr/testify/assert"
)

func TestPasswordHashAndCompare(t *testing.T) {
	assert := assert.New(t)

	var (
		password = "secret"
	)
	hash, err := passwd.Encrypt(password)
	log.Println(hash)
	assert.Nil(err)

	err = passwd.Compare(password, hash)
	assert.Nil(err)
}

func TestEmptyPassword(t *testing.T) {
	assert := assert.New(t)

	_, err := passwd.Encrypt("")
	assert.NotNil(err)
}

func TestCompare(t *testing.T) {
	assert := assert.New(t)
	err := passwd.Compare("", "")
	assert.NotNil(err)
	assert.Equal(err, passwd.ErrPasswordRequired)

	err = passwd.Compare("x", "")
	assert.NotNil(err)
	assert.Equal(err, passwd.ErrPasswordRequired)

	err = passwd.Compare("", "x")
	assert.NotNil(err)
	assert.Equal(err, passwd.ErrPasswordRequired)

	err = passwd.Compare("x", "x")
	assert.NotNil(err)
	assert.Equal(err, passwd.ErrHashInvalid)

	err = passwd.Compare("x", "$a$b$c$d")
	assert.NotNil(err)
	assert.Equal("unknown password hashing function identifier", err.Error())

	err = passwd.Compare("x", "$argon2id$b$c$d")
	assert.NotNil(err)
	assert.Equal("illegal base64 data at input byte 0", err.Error())
}
