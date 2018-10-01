# passwd

Password hashing with argon2id, winner of the Password Hashing Competition in 2015. A replacement for bcrypt.



## Usage

By default, it will use the basic configuration suggested for the argon2id hasher:

```go
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
```

Output:

```
$argon2id$m=65536,t=2,p=4$HvNaNwCf4Bn55RLuR8uu1g==$e7ZgRsnRbZaFkXs2ogmbD5dt/mF5B0IAvOTYDr0ebZI=
```

## Custom 

There is a factory provided to customize the configuration for the hasher:

```go
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
	hash, err := hasher.Hash(password)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(hash)

	err = hasher.Verify(password, hash)
	if err != nil {
		log.Fatal(err)
	}
}
```

Output:

```
$argon2id$m=65536,t=2,p=4$ylby4LzuL0HRUW8MYKabENOgbX1NhOBSMDxSRkAMkQQ=$iDtW/fLs+vxsZQeDu3Aq/5JB9wTq4qG2OksocjLcdg0LaxTdOJtLHaDvN65XZB1ypP4v+K4rTOKQUHNaBWKNt/4fDNOVTXT5KExrZ+jRi+n1Wwd7L
BXVhqGofieSZRoPiBv1YA==
```
