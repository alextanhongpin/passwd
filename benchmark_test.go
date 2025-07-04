package passwd_test

import (
	"testing"

	"github.com/alextanhongpin/passwd"
)

func BenchmarkEncrypt(b *testing.B) {
	password := "benchmarkpassword"
	for i := 0; i < b.N; i++ {
		_, err := passwd.Encrypt(password)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCompare(b *testing.B) {
	password := "benchmarkpassword"
	hash, err := passwd.Encrypt(password)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := passwd.Compare(hash, password)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncryptCustom(b *testing.B) {
	password := "benchmarkpassword"
	hasher := passwd.New().WithParams(1, 32*1024, 2, 32, 16)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := hasher.Encrypt(password)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCompareCustom(b *testing.B) {
	password := "benchmarkpassword"
	hasher := passwd.New().WithParams(1, 32*1024, 2, 32, 16)
	hash, err := hasher.Encrypt(password)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := hasher.Compare(hash, password)
		if err != nil {
			b.Fatal(err)
		}
	}
}
