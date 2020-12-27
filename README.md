# CryptoolZ: Cryptographic tools for developing Zero-knowledge applications

This repository contains a bunch of cryptographic primitives coded in C, intended to be used (but not limited to) in Zero-Knowledge applications. Currently we support:

- [EdDSA](https://eprint.iacr.org/2015/677.pdf) signature algorithm over [Baby JubJub](https://iden3-docs.readthedocs.io/en/latest/_downloads/33717d75ab84e11313cc0d8a090b636f/Baby-Jubjub.pdf) elliptic curve.
- [MiMC-7](https://eprint.iacr.org/2016/492.pdf) hashing function (BN128 order).

**DISCLAIMER:** this implementation **has not gone through an exhaustive security analysis**, so it is not intended to be used in a production environment, only for academic purposes.

## Preliminaries
To use the library, we need [GMP](https://gmplib.org/) and [OpenSSL](https://www.openssl.org/). To install them, simply run:

``sudo apt-get install ligmp-dev openssl``

## Usage
### Compile and test
In order to compile and test the different tools, simply run:

``gcc tests.c -o tests -lgmp -lcrypto && ./tests``

If all tests appear as PASSED, you are ready to go! In order to use the library, you need to include the following header and to initialize the public BN128 and Baby JubJub parameters: 

```c
#include "lib/cryptoolz.h"

int main()
{
	init_public_parameters();
	return 0;
}
```

### MiMC

The MiMC hashing function can be used to generate the hash of a value `x_in` using a hashing key `k`, as follows:

```c
mpz_t hash, x_in, k;
mpz_inits(hash, x_in, k, NULL);
mpz_set_str(x_in, "0011223344", 10);
mpz_set_str(k, "1234", 10);
mimc7(&hash, &x_in, &k);
```

Alternatively, we can hash an array of values using each previous hashed value as a key for the new hash, like this:

```c
int size = 4;
mpz_t hash, arr[size];
mpz_init(hash);

for (int i = 0; i < size; i++)
{
	mpz_init(arr[i]);
	mpz_set_str(arr[i], "0011223344", 10);
}

multi_mimc7(&hash, arr, &size);
```

### EdDSA
#### Generate keypair
We set a secret key which will be hashed using SHA512, and the 256 most significant bits will be set to `sk.hsk`. The 256 least significant bits are set to `sk.s`. This value is used to compute the public key `(A1, A2) = s * (B1, B2)`. You can generate this keypair as follows:

```c
secretKey sk;
sk.sk = "00112233445566778899";	
publicKey pk;
generate_keypair(&pk, &sk);
```
#### Sign a message
In order to sign `message`, a value `r` is computed by `sign_message(...)` as follows: `r = SHA512(hsk, message)`. This value is used to compute `(R1, R2) = r * (B1, B2)` and `S = r + MiMC7(R1, R2, A1, A2, message) * s`. As can be seen, the hash function we use is MiMC7. In order to sign a message, we do as follows:

```c
char *message = "1234";
signature sig;
sign_message(&sig, message, &sk, &pk);
```

#### Verify a signature
We verify a signature `(R1, R2, S)` of `message` using the public key `(A1, A2)`, by checking if the following equation holds: `S * (B1, B2) = (R1, R2) + MiMC7(R1, R2, A1, A2, message) * (A1, A2)`. As can be seen, we use a *cofactorless verification*. In order to verify a signature, we do as follows:

```c
int isVerified = verify_signature(&sig, message, &pk);
printf("Is verified: %d\n", isVerified);
```

In the root directory of the repository you can find `eddsa_example.c` with the code above provided.
