package passwd

// New returns a new argon2id hasher with default configurations if none is
// provided.
func New(opts ...Option) Argon2id {
	a := Argon2id{
		time:        time,
		memory:      memory,
		parallelism: parallelism,
		keyLen:      keyLen,
		saltLen:     saltLen,
	}
	for _, o := range opts {
		o(&a)
	}
	return a
}

// Argon2id contains the configuration for the argon2id hashing function.
type Argon2id struct {
	time        uint32
	memory      uint32
	parallelism uint8
	keyLen      uint32
	saltLen     uint32
}

type Option func(*Argon2id)

// Time sets the current time.
func Time(t uint32) Option {
	return func(a *Argon2id) {
		a.time = t
	}
}

// Memory sets the current memory.
func Memory(m uint32) Option {
	return func(a *Argon2id) {
		a.memory = m
	}
}

// Parallelism sets the current parallelism.
func Parallelism(p uint8) Option {
	return func(a *Argon2id) {
		a.parallelism = p
	}
}

// SaltLen sets the current salt len.
func SaltLen(s uint32) Option {
	return func(a *Argon2id) {
		a.saltLen = s
	}
}

// KeyLen sets the current key len.
func KeyLen(k uint32) Option {
	return func(a *Argon2id) {
		a.keyLen = k
	}
}

// Encrypt hashes a raw-text password and return the hashed password.
func (a *Argon2id) Encrypt(password []byte) (string, error) {
	return encrypt(password, a.parallelism, a.saltLen, a.time, a.memory, a.keyLen)
}

// Compare attempts to compare the password with the hash in constant-time compare.
func (a *Argon2id) Compare(phc string, password []byte) (bool, error) {
	return compare(password, phc, a.keyLen)
}
