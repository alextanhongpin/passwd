[![](https://godoc.org/github.com/alextanhongpin/passwd?status.svg)](http://godoc.org/github.com/alextanhongpin/passwd)


# passwd

Password hashing with argon2id, winner of the Password Hashing Competition in 2015. A replacement for bcrypt.



## Usage

By default, it will use the basic configuration suggested for the argon2id hasher:

```go
package main

import (
	"fmt"

	"github.com/alextanhongpin/passwd"
)

func main() {
	password := "supersecret"
	hash, err := passwd.Encrypt(password)
	if err != nil {
		panic(err)
	}
	fmt.Println(hash)

	if err := passwd.Compare(hash, password); err != nil {
		panic(err)
	}

}
```

Output:

```
$argon2id$v=19$m=65536,t=2,p=4$B0NlB8p842k+j0YklUVkFQ==$fXKoOgOf/E7w5B0CleSjcp3AM9dezSaIcMD99ZruBOs=
```

## Custom

You can customize the params by creating a new instance of the hasher:

```go
package main

import (
	"fmt"

	"github.com/alextanhongpin/passwd"
)

func main() {
	password := "supersecret"
	hasher := passwd.Argon2id{
		Time:        1,
		Memory:      32 * 1024,
		Parallelism: 2,
		SaltLen:     32,
		KeyLen:      32,
	}
	hash, err := hasher.Encrypt(password)
	if err != nil {
		panic(err)
	}
	fmt.Println(hash)

	if err := hasher.Compare(hash, password); err != nil {
		panic(err)
	}
}
```

Output:

```
$argon2id$v=19$m=32768,t=1,p=2$92ncFMfyN15MDGrwFTV9jmC727qkz/Yo5VNzC4GSgZE=$ZJwi+8hhxvqfYU7BzpD1tvZ1o/Dlrh8/wAKbJ6IARKw=
```
