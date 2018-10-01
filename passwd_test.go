package passwd_test

import (
	"log"
	"testing"

	"github.com/alextanhongpin/passwd"

	"github.com/stretchr/testify/assert"
)

func TestPasswordHashAndVerify(t *testing.T) {
	assert := assert.New(t)

	var (
		password = "secret"
	)
	hash, err := passwd.Hash(password)
	log.Println(hash)
	assert.Nil(err)

	err = passwd.Verify(password, hash)
	assert.Nil(err)
}

func TestEmptyPassword(t *testing.T) {
	assert := assert.New(t)

	_, err := passwd.Hash("")
	assert.NotNil(err)
}

func TestVerify(t *testing.T) {
	assert := assert.New(t)
	err := passwd.Verify("", "")
	assert.NotNil(err)
	assert.Equal("arguments len cannot be zero", err.Error())

	err = passwd.Verify("x", "")
	assert.NotNil(err)
	assert.Equal("arguments len cannot be zero", err.Error())

	err = passwd.Verify("", "x")
	assert.NotNil(err)
	assert.Equal("arguments len cannot be zero", err.Error())

	err = passwd.Verify("x", "x")
	assert.NotNil(err)
	assert.Equal("invalid hash format", err.Error())

	err = passwd.Verify("x", "$a$b$c$d")
	assert.NotNil(err)
	assert.Equal("unknown password hashing function identifier", err.Error())

	err = passwd.Verify("x", "$argon2id$b$c$d")
	assert.NotNil(err)
	assert.Equal("illegal base64 data at input byte 0", err.Error())
}
