[![](https://godoc.org/github.com/alextanhongpin/passwd?status.svg)](http://godoc.org/github.com/alextanhongpin/passwd)

# passwd

Secure password hashing library for Go using Argon2id, the winner of the Password Hashing Competition in 2015. A modern replacement for bcrypt with better security against both side-channel and GPU cracking attacks.

## Features

- **Secure**: Uses Argon2id algorithm with secure default parameters
- **Unicode-aware**: Handles password normalization for international characters
- **Flexible**: Customizable parameters for different security requirements
- **Standard-compliant**: Uses PHC (Password Hashing Competition) string format
- **Well-tested**: Comprehensive test suite with edge cases
- **Zero dependencies**: Only depends on Go standard library and golang.org/x/crypto

## Installation

```bash
go get github.com/alextanhongpin/passwd
```

## Quick Start

The simplest way to use the library is with the default configuration:

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/alextanhongpin/passwd"
)

func main() {
    password := "supersecret"
    
    // Hash the password
    hash, err := passwd.Encrypt(password)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Hash:", hash)
    
    // Verify the password
    if err := passwd.Compare(hash, password); err != nil {
        log.Fatal("Password verification failed:", err)
    }
    fmt.Println("Password verified successfully!")
}
```

## Basic Usage Patterns

### Simple Password Hashing

```go
func hashPassword(password string) (string, error) {
    return passwd.Encrypt(password)
}

func verifyPassword(hash, password string) bool {
    return passwd.Compare(hash, password) == nil
}
```

### User Registration

```go
type User struct {
    ID       int
    Username string
    Password string // This will store the hash
}

func registerUser(username, password string) (*User, error) {
    // Hash the password
    hash, err := passwd.Encrypt(password)
    if err != nil {
        return nil, fmt.Errorf("failed to hash password: %w", err)
    }
    
    user := &User{
        Username: username,
        Password: hash,
    }
    
    // Save user to database...
    
    return user, nil
}
```

### User Authentication

```go
func authenticateUser(username, password string) (*User, error) {
    // Fetch user from database...
    user, err := getUserByUsername(username)
    if err != nil {
        return nil, err
    }
    
    // Verify password
    if err := passwd.Compare(user.Password, password); err != nil {
        return nil, fmt.Errorf("invalid credentials")
    }
    
    return user, nil
}
```

## Custom Configuration

For applications with specific security requirements, you can create custom hashers:

### Method 1: Using New() and modifying fields

```go
func createCustomHasher() *passwd.Argon2id {
    hasher := passwd.New()
    hasher.Time = 3         // 3 iterations (more secure, slower)
    hasher.Memory = 128 * 1024  // 128 MB memory
    hasher.Parallelism = 2  // 2 parallel threads
    return hasher
}

func main() {
    password := "supersecret"
    hasher := createCustomHasher()
    
    // Always validate parameters before use
    if err := hasher.Validate(); err != nil {
        log.Fatal("Invalid parameters:", err)
    }
    
    hash, err := hasher.Encrypt(password)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Hash:", hash)
    
    if err := hasher.Compare(hash, password); err != nil {
        log.Fatal("Password verification failed:", err)
    }
    fmt.Println("Password verified successfully!")
}
```

### Method 2: Using WithParams() method

```go
func main() {
    password := "supersecret"
    
    // Create a custom hasher using the builder pattern
    hasher := passwd.New().WithParams(
        1,          // time: 1 iteration (faster)
        32*1024,    // memory: 32 MB
        2,          // parallelism: 2 threads
        32,         // keyLen: 32 bytes
        16,         // saltLen: 16 bytes
    )
    
    if err := hasher.Validate(); err != nil {
        log.Fatal("Invalid parameters:", err)
    }
    
    hash, err := hasher.Encrypt(password)
    if err != nil {
        log.Fatal(err)
    }
    
    // Verify password
    if err := hasher.Compare(hash, password); err != nil {
        log.Fatal("Password verification failed:", err)
    }
    
    fmt.Println("Custom hashing successful!")
}
```

### Method 3: Direct struct initialization

```go
func main() {
    password := "supersecret"
    
    // Create hasher with direct struct initialization
    hasher := &passwd.Argon2id{
        Time:        2,
        Memory:      64 * 1024,
        Parallelism: 4,
        KeyLen:      32,
        SaltLen:     16,
    }
    
    hash, err := hasher.Encrypt(password)
    if err != nil {
        log.Fatal(err)
    }
    
    if err := hasher.Compare(hash, password); err != nil {
        log.Fatal("Password verification failed:", err)
    }
    
    fmt.Println("Direct initialization successful!")
}
```

## Advanced Usage

### Deterministic Hashing for Testing

```go
func TestPasswordHashing(t *testing.T) {
    hasher := passwd.New()
    password := "testpassword"
    
    // Create a fixed salt for deterministic testing
    salt := make([]byte, 16)
    for i := range salt {
        salt[i] = byte(i)
    }
    
    hash1, err := hasher.Hash(password, salt)
    require.NoError(t, err)
    
    hash2, err := hasher.Hash(password, salt)
    require.NoError(t, err)
    
    // Same password and salt should produce identical hashes
    assert.Equal(t, hash1, hash2)
}
```

### Password Upgrade Strategy

```go
func upgradePasswordIfNeeded(userID int, hash, password string) error {
    // Check if the current hash needs to be upgraded
    if passwd.NeedsRehash(hash) {
        // Generate new hash with current parameters
        newHash, err := passwd.Encrypt(password)
        if err != nil {
            return fmt.Errorf("failed to rehash password: %w", err)
        }
        
        // Update user's password hash in database
        return updateUserPassword(userID, newHash)
    }
    
    return nil
}

func authenticateAndUpgrade(username, password string) (*User, error) {
    user, err := getUserByUsername(username)
    if err != nil {
        return nil, err
    }
    
    // Verify current password
    if err := passwd.Compare(user.Password, password); err != nil {
        return nil, fmt.Errorf("invalid credentials")
    }
    
    // Upgrade password hash if needed
    if err := upgradePasswordIfNeeded(user.ID, user.Password, password); err != nil {
        // Log error but don't fail authentication
        log.Printf("Failed to upgrade password for user %d: %v", user.ID, err)
    }
    
    return user, nil
}
```

### Environment-Specific Configuration

```go
type Config struct {
    Environment string
    Argon2id    passwd.Argon2id
}

func newConfig(env string) *Config {
    config := &Config{Environment: env}
    
    switch env {
    case "development":
        // Faster parameters for development
        config.Argon2id = passwd.Argon2id{
            Time:        1,
            Memory:      16 * 1024,
            Parallelism: 2,
            KeyLen:      32,
            SaltLen:     16,
        }
    case "testing":
        // Even faster for tests
        config.Argon2id = passwd.Argon2id{
            Time:        1,
            Memory:      8 * 1024,
            Parallelism: 1,
            KeyLen:      32,
            SaltLen:     16,
        }
    default: // production
        // Use secure defaults
        config.Argon2id = *passwd.New()
    }
    
    return config
}

func main() {
    env := os.Getenv("ENV")
    if env == "" {
        env = "production"
    }
    
    config := newConfig(env)
    hasher := &config.Argon2id
    
    // Use hasher throughout your application
    password := "userpassword"
    hash, err := hasher.Encrypt(password)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Hashed password in %s environment\n", env)
}
```

## Parameter Guidelines

The library provides secure defaults, but you can adjust parameters based on your needs:

- **Time**: Number of iterations (default: 2)
  - Higher values = more secure but slower
  - Recommended: 1-3 for most applications
  
- **Memory**: Memory usage in KB (default: 64MB)
  - Higher values = more secure but uses more RAM
  - Recommended: 32MB-128MB for most applications
  
- **Parallelism**: Number of parallel threads (default: 4)
  - Should match your CPU cores
  - Recommended: 1-8 for most applications

- **KeyLen**: Length of derived key (default: 32 bytes)
  - 32 bytes provides excellent security
  - Minimum recommended: 16 bytes

- **SaltLen**: Length of salt (default: 16 bytes)
  - 16 bytes is sufficient for most use cases
  - Minimum recommended: 16 bytes

## Security Features

### Unicode Normalization
The library automatically normalizes passwords using NFKC normalization, ensuring consistent behavior across different devices and input methods:

```go
func demonstrateUnicodeNormalization() {
    // These passwords will be treated as equivalent:
    password1 := "café"     // e with acute accent (single character)
    password2 := "café"     // e + combining acute accent (two characters)
    
    hash, err := passwd.Encrypt(password1)
    if err != nil {
        log.Fatal(err)
    }
    
    // This will succeed even though the strings are different
    if err := passwd.Compare(hash, password2); err != nil {
        log.Fatal("Unicode normalization failed")
    }
    
    fmt.Println("Unicode normalization works correctly!")
}
```

### Constant-Time Comparison
All password comparisons use constant-time algorithms to prevent timing attacks.

### Secure Random Salt Generation
Each password hash uses a cryptographically secure random salt to prevent rainbow table attacks.

### Hash Information Extraction

```go
func analyzeHash(hashString string) {
    result, err := passwd.Parse(hashString)
    if err != nil {
        log.Fatal("Failed to parse hash:", err)
    }
    
    fmt.Printf("Hash Analysis:\n")
    fmt.Printf("  Time: %d iterations\n", result.Argon2id.Time)
    fmt.Printf("  Memory: %d KB\n", result.Argon2id.Memory)
    fmt.Printf("  Parallelism: %d threads\n", result.Argon2id.Parallelism)
    fmt.Printf("  Key Length: %d bytes\n", result.Argon2id.KeyLen)
    fmt.Printf("  Salt Length: %d bytes\n", result.Argon2id.SaltLen)
}
```

## Error Handling

The library provides specific error types for different failure scenarios:

```go
import "errors"

func handlePasswordHashing(password string) {
    hash, err := passwd.Encrypt(password)
    if err != nil {
        switch {
        case errors.Is(err, passwd.ErrEmptyPassword):
            fmt.Println("Error: Password cannot be empty")
        case errors.Is(err, passwd.ErrGenerateSalt):
            fmt.Println("Error: Failed to generate salt")
        case errors.Is(err, passwd.ErrInvalidParameters):
            fmt.Println("Error: Invalid hasher parameters")
        default:
            fmt.Printf("Error: %v\n", err)
        }
        return
    }
    
    // Test verification
    err = passwd.Compare(hash, password)
    if err != nil {
        switch {
        case errors.Is(err, passwd.ErrWrongPassword):
            fmt.Println("Error: Password verification failed")
        case errors.Is(err, passwd.ErrInvalidHash):
            fmt.Println("Error: Hash format is invalid")
        case errors.Is(err, passwd.ErrEmptyPassword):
            fmt.Println("Error: Password cannot be empty")
        default:
            fmt.Printf("Error: %v\n", err)
        }
        return
    }
    
    fmt.Println("Password hashing and verification successful!")
}
```

## Web Application Example

Here's a complete example of using the library in a web application:

```go
package main

import (
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    
    "github.com/alextanhongpin/passwd"
)

type User struct {
    ID       int    `json:"id"`
    Username string `json:"username"`
    Password string `json:"-"` // Never expose password hash in JSON
}

type RegisterRequest struct {
    Username string `json:"username"`
    Password string `json:"password"`
}

type LoginRequest struct {
    Username string `json:"username"`
    Password string `json:"password"`
}

var users = make(map[string]*User) // In-memory store for demo
var nextID = 1

func registerHandler(w http.ResponseWriter, r *http.Request) {
    var req RegisterRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request", http.StatusBadRequest)
        return
    }
    
    // Validate input
    if req.Username == "" || req.Password == "" {
        http.Error(w, "Username and password required", http.StatusBadRequest)
        return
    }
    
    // Check if user already exists
    if _, exists := users[req.Username]; exists {
        http.Error(w, "User already exists", http.StatusConflict)
        return
    }
    
    // Hash password
    hash, err := passwd.Encrypt(req.Password)
    if err != nil {
        log.Printf("Password hashing failed: %v", err)
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }
    
    // Create user
    user := &User{
        ID:       nextID,
        Username: req.Username,
        Password: hash,
    }
    nextID++
    
    users[req.Username] = user
    
    // Return user (without password)
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(user)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
    var req LoginRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request", http.StatusBadRequest)
        return
    }
    
    // Find user
    user, exists := users[req.Username]
    if !exists {
        http.Error(w, "Invalid credentials", http.StatusUnauthorized)
        return
    }
    
    // Verify password
    if err := passwd.Compare(user.Password, req.Password); err != nil {
        http.Error(w, "Invalid credentials", http.StatusUnauthorized)
        return
    }
    
    // Optionally upgrade password if needed
    if passwd.NeedsRehash(user.Password) {
        if newHash, err := passwd.Encrypt(req.Password); err == nil {
            user.Password = newHash
            log.Printf("Upgraded password hash for user %s", user.Username)
        }
    }
    
    // Return success
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{
        "message": "Login successful",
        "user":    user.Username,
    })
}

func main() {
    http.HandleFunc("/register", registerHandler)
    http.HandleFunc("/login", loginHandler)
    
    fmt.Println("Server starting on :8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

## Hash Format

The library produces hashes in the PHC (Password Hashing Competition) string format:

```
$argon2id$v=19$m=65536,t=2,p=4$B0NlB8p842k+j0YklUVkFQ==$fXKoOgOf/E7w5B0CleSjcp3AM9dezSaIcMD99ZruBOs=
```

Breaking this down:
- `$argon2id$`: Algorithm identifier
- `v=19`: Argon2 version
- `m=65536,t=2,p=4`: Memory=64MB, Time=2 iterations, Parallelism=4 threads
- `B0NlB8p842k+j0YklUVkFQ==`: Base64-encoded salt
- `fXKoOgOf/E7w5B0CleSjcp3AM9dezSaIcMD99ZruBOs=`: Base64-encoded hash

## Testing

Run the test suite:

```bash
go test ./...
```

Run tests with coverage:

```bash
go test -cover ./...
```

Run benchmarks:

```bash
go test -bench=. -benchtime=5s
```

### Testing Your Own Code

When testing code that uses password hashing, you can use deterministic hashing:

```go
func TestUserRegistration(t *testing.T) {
    // Create a hasher for testing
    hasher := passwd.New()
    
    // Use a fixed salt for deterministic results
    salt := make([]byte, 16)
    for i := range salt {
        salt[i] = byte(i)
    }
    
    password := "testpassword"
    expectedHash, err := hasher.Hash(password, salt)
    require.NoError(t, err)
    
    // Test your registration function
    user, err := registerUser("testuser", password)
    require.NoError(t, err)
    
    // Verify the password can be verified
    err = hasher.Compare(user.Password, password)
    assert.NoError(t, err)
}
```

## Performance

The library is designed to be secure by default, which means it will be slower than less secure alternatives like bcrypt. The default parameters are chosen to provide strong security while maintaining reasonable performance on modern hardware.

### Benchmark Results

On an Apple M3 Pro:
- **Default parameters**: ~22ms per hash
- **Custom fast parameters**: ~9ms per hash

```bash
BenchmarkEncrypt-11          	      51	  22577320 ns/op
BenchmarkCompare-11          	      52	  24197463 ns/op
BenchmarkEncryptCustom-11    	     130	   9234833 ns/op
BenchmarkCompareCustom-11    	     133	   9075666 ns/op
```

### Performance Tuning

For performance-critical applications, you can adjust parameters:

```go
// Faster parameters (less secure)
fastHasher := &passwd.Argon2id{
    Time:        1,      // 1 iteration
    Memory:      16 * 1024, // 16 MB
    Parallelism: 2,      // 2 threads
    KeyLen:      32,
    SaltLen:     16,
}

// Slower parameters (more secure)
secureHasher := &passwd.Argon2id{
    Time:        4,      // 4 iterations
    Memory:      128 * 1024, // 128 MB
    Parallelism: 8,      // 8 threads
    KeyLen:      32,
    SaltLen:     16,
}
```

## Migration from bcrypt

If you're migrating from bcrypt, you can gradually transition:

### Strategy 1: Gradual Migration

```go
import (
    "golang.org/x/crypto/bcrypt"
    "github.com/alextanhongpin/passwd"
)

func verifyPasswordWithFallback(hash, password string) error {
    // Try Argon2id first
    if err := passwd.Compare(hash, password); err == nil {
        return nil
    }
    
    // Fallback to bcrypt
    return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

func upgradeFromBcrypt(userID int, hash, password string) error {
    // Verify it's a bcrypt hash first
    if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
        return err
    }
    
    // Create new Argon2id hash
    newHash, err := passwd.Encrypt(password)
    if err != nil {
        return err
    }
    
    // Update user's password hash in database
    return updateUserPassword(userID, newHash)
}
```

### Strategy 2: Detection-based Migration

```go
func isBcryptHash(hash string) bool {
    return strings.HasPrefix(hash, "$2a$") || 
           strings.HasPrefix(hash, "$2b$") || 
           strings.HasPrefix(hash, "$2y$")
}

func authenticateWithMigration(username, password string) (*User, error) {
    user, err := getUserByUsername(username)
    if err != nil {
        return nil, err
    }
    
    var needsUpgrade bool
    
    if isBcryptHash(user.Password) {
        // Verify bcrypt hash
        if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
            return nil, fmt.Errorf("invalid credentials")
        }
        needsUpgrade = true
    } else {
        // Verify Argon2id hash
        if err := passwd.Compare(user.Password, password); err != nil {
            return nil, fmt.Errorf("invalid credentials")
        }
        
        // Check if Argon2id hash needs upgrade
        needsUpgrade = passwd.NeedsRehash(user.Password)
    }
    
    // Upgrade hash if needed
    if needsUpgrade {
        if newHash, err := passwd.Encrypt(password); err == nil {
            user.Password = newHash
            updateUserPassword(user.ID, newHash)
        }
    }
    
    return user, nil
}
```

## API Reference

### Package Functions

```go
// Hash a password with default parameters
func Encrypt(password string) (string, error)

// Verify a password against a hash
func Compare(hash, password string) error

// Check if a hash needs to be rehashed with current default parameters
func NeedsRehash(hash string) bool

// Parse a hash string into components
func Parse(s string) (*Result, error)
```

### Argon2id Type

```go
type Argon2id struct {
    Time        uint32  // Number of iterations
    Memory      uint32  // Memory usage in KB
    Parallelism uint8   // Number of parallel threads
    KeyLen      uint32  // Length of derived key in bytes
    SaltLen     uint32  // Length of salt in bytes
}

// Create hasher with recommended defaults
func New() *Argon2id

// Create hasher with custom parameters
func (a *Argon2id) WithParams(time, memory uint32, parallelism uint8, keyLen, saltLen uint32) *Argon2id

// Validate parameters
func (a *Argon2id) Validate() error

// Hash a password
func (a *Argon2id) Encrypt(password string) (string, error)

// Hash a password with provided salt (for testing)
func (a *Argon2id) Hash(password string, salt []byte) (string, error)

// Verify a password
func (a *Argon2id) Compare(hash, password string) error

// Check if hash needs rehashing with this hasher's parameters
func (a *Argon2id) NeedsRehash(hash string) bool
```

### Error Types

```go
var (
    ErrDecodeBase64      = errors.New("passwd: error decoding base64")
    ErrEmptyPassword     = errors.New("passwd: password must not be empty")
    ErrGenerateSalt      = errors.New("passwd: error generating salt")
    ErrInvalidHash       = errors.New("passwd: invalid argon2id hash")
    ErrWrongPassword     = errors.New("passwd: wrong password")
    ErrInvalidParameters = errors.New("passwd: invalid parameters")
)
```

## Contributing

Contributions are welcome! Please ensure:

1. All tests pass: `go test ./...`
2. Code is formatted: `go fmt ./...`
3. Code is linted: `go vet ./...`
4. Add tests for new features
5. Update documentation as needed

## License

BSD 3-Clause License

Copyright (c) 2022, Alex Tan Hong Pin
All rights reserved.
