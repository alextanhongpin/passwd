package main

import (
	"fmt"
	"log"

	"github.com/alextanhongpin/passwd"
)

func main() {
	fmt.Println("=== Password Hashing with Argon2id ===")
	fmt.Println()

	// Example 1: Basic usage with default parameters
	fmt.Println("1. Basic Usage:")
	password := "mysecretpassword"
	hash, err := passwd.Encrypt(password)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("   Password: %s\n", password)
	fmt.Printf("   Hash: %s\n", hash)

	// Verify the password
	err = passwd.Compare(hash, password)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("   ✓ Password verification successful")

	// Try with wrong password
	err = passwd.Compare(hash, "wrongpassword")
	if err != nil {
		fmt.Printf("   ✓ Wrong password correctly rejected: %s\n", err)
	}

	fmt.Println()

	// Example 2: Custom parameters
	fmt.Println("2. Custom Parameters:")
	customHasher := passwd.New().WithParams(1, 32*1024, 2, 32, 16)
	err = customHasher.Validate()
	if err != nil {
		log.Fatal(err)
	}

	customHash, err := customHasher.Encrypt(password)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("   Custom Hash: %s\n", customHash)

	err = customHasher.Compare(customHash, password)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("   ✓ Custom hasher verification successful")

	fmt.Println()

	// Example 3: Rehash checking
	fmt.Println("3. Rehash Checking:")
	needsRehash := passwd.NeedsRehash(customHash)
	fmt.Printf("   Custom hash needs rehash with default params: %t\n", needsRehash)

	needsRehash = customHasher.NeedsRehash(customHash)
	fmt.Printf("   Custom hash needs rehash with same params: %t\n", needsRehash)

	fmt.Println()

	// Example 4: Unicode support
	fmt.Println("4. Unicode Support:")
	unicodePassword := "🔒🔑密码café"
	unicodeHash, err := passwd.Encrypt(unicodePassword)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("   Unicode Password: %s\n", unicodePassword)
	fmt.Printf("   Unicode Hash: %s\n", unicodeHash)

	err = passwd.Compare(unicodeHash, unicodePassword)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("   ✓ Unicode password verification successful")

	fmt.Println()

	// Example 5: Hash parsing
	fmt.Println("5. Hash Parsing:")
	result, err := passwd.Parse(hash)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("   Parsed parameters:\n")
	fmt.Printf("   - Time: %d\n", result.Argon2id.Time)
	fmt.Printf("   - Memory: %d KB\n", result.Argon2id.Memory)
	fmt.Printf("   - Parallelism: %d\n", result.Argon2id.Parallelism)
	fmt.Printf("   - Key Length: %d bytes\n", result.Argon2id.KeyLen)
	fmt.Printf("   - Salt Length: %d bytes\n", result.Argon2id.SaltLen)

	fmt.Println("\n=== All examples completed successfully! ===")
}
