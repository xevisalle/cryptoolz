
void add(mpz_t *uOut, mpz_t *vOut, mpz_t *u1, mpz_t *v1, mpz_t *u2, mpz_t *v2)
{
	mpz_t f1, f2, f3, f4, f5;
	mpz_inits(f1, f2, f3, f4, f5, NULL);

	// uOut = (u1*v2 + v1*u2) / (1 + d*u1*u2*v1*v2)
	mpz_mul(f1, *u1, *v2);
	mpz_mul(f2, *v1, *u2);
	mpz_add(f3, f1, f2);

	mpz_mul(f1, f1, f2);
	mpz_mul(f4, f1, d);
	mpz_add_ui(f1, f4, 1);
	mpz_invert(f1, f1, pPrime);
	mpz_mul(f3, f3, f1);
	mpz_mod(f3, f3, pPrime);

	// vOut = (v1*v2 - a*u1*u2) / (1 - d*u1*u2*v1*v2)
	mpz_mul(f1, *v1, *v2);
	mpz_mul(f2, *u1, *u2);
	mpz_mul(f2, f2, a);
	mpz_sub(f5, f1, f2);

	mpz_neg(f4, f4);
	mpz_add_ui(f1, f4, 1);
	mpz_invert(f1, f1, pPrime);
	mpz_mul(f5, f5, f1);
	mpz_mod(*vOut, f5, pPrime);

	mpz_set(*uOut, f3);
	mpz_clears(f1, f2, f3, f4, f5, NULL);
}

void mul_scalar(mpz_t *mulOut1, mpz_t *mulOut2, mpz_t *doubledP10, mpz_t *doubledP20, char *exponent, int *size)
{
	mpz_t accumulatedP1;
	mpz_t accumulatedP2;
	mpz_init_set_ui(accumulatedP1, 0);
	mpz_init_set_ui(accumulatedP2, 1);

	mpz_t candidateP1;
	mpz_t candidateP2;
	mpz_init(candidateP1);
	mpz_init(candidateP2);

	mpz_t doubledP1;
	mpz_t doubledP2;
	mpz_init_set(doubledP1, *doubledP10);
	mpz_init_set(doubledP2, *doubledP20);

	int j;
	for (int i = 0; i < *size; i++)
	{
		j = *size - 1 - i;
		add(&candidateP1, &candidateP2, &accumulatedP1, &accumulatedP2, &doubledP1, &doubledP2);

		if (exponent[j])
		{
			mpz_set(accumulatedP1, candidateP1);
			mpz_set(accumulatedP2, candidateP2);
		}

		add(&doubledP1, &doubledP2, &doubledP1, &doubledP2, &doubledP1, &doubledP2);
	}

	mpz_set(*mulOut1, accumulatedP1);
	mpz_set(*mulOut2, accumulatedP2);

	mpz_clears(accumulatedP1, accumulatedP2, candidateP1, candidateP2, doubledP1, doubledP2, NULL);
}

int get_size(mpz_t *val)
{
	char sBits[512];
	mpz_get_str(sBits, 2, *val);
	return strlen(sBits);
}

void to_bits(char *bits, mpz_t *val)
{
	mpz_get_str(bits, 2, *val);
	int size = strlen(bits);

	for (int i = 0; i < size; i++)
	{
		if ((int)(bits[i]) == 49) bits[i] = 1;
		else bits[i] = 0;
	}
}

int verify_signature(signature *sig, char *message, publicKey *pk)
{
	mpz_t SB1;
	mpz_t SB2;
	mpz_init(SB1);
	mpz_init(SB2);

	int size = get_size(&sig->S);
	char sBits[size];
	to_bits(sBits, &sig->S);

	mul_scalar(&SB1, &SB2, &B1, &B2, sBits, &size);

	size = 5;
	mpz_t arr[size];
	mpz_init_set(arr[0], sig->R1);
	mpz_init_set(arr[1], sig->R2);
	mpz_init_set(arr[2], pk->A1);
	mpz_init_set(arr[3], pk->A2);
	mpz_init_set_str(arr[4], message, 10);

	mpz_t hash;
	mpz_init(hash);

	multi_mimc7(&hash, arr, &size);
	size = get_size(&hash);
	char hBits[size];
	to_bits(hBits, &hash);

	mpz_t R8hA1;
	mpz_t R8hA2;
	mpz_init(R8hA1);
	mpz_init(R8hA2);

	mul_scalar(&R8hA1, &R8hA2, &arr[2], &arr[3], hBits, &size);
	add(&R8hA1, &R8hA2, &R8hA1, &R8hA2, &arr[0], &arr[1]);

	int verified = 0;
	if (mpz_cmp(SB1, R8hA1) == 0 && mpz_cmp(SB2, R8hA2) == 0) verified = 1;

	for (int i = 0; i < 5; i++)
	{
		mpz_clear(arr[i]);
	}

	mpz_clears(R8hA1, R8hA2, hash, SB1, SB2, NULL);

	return verified;
}

void generate_keypair(publicKey *pk, secretKey *sk)
{
	unsigned char hash[SHA512_DIGEST_LENGTH];

    SHA512_CTX sha512;
    SHA512_Init(&sha512);
    SHA512_Update(&sha512, sk->sk, strlen(sk->sk));
    SHA512_Final(hash, &sha512);

	char hashString[SHA512_DIGEST_LENGTH/2];
	for(int i = 0; i < SHA512_DIGEST_LENGTH/2; i++)
	{
		sprintf(&sk->hsk[i*2], "%02x", (unsigned int)hash[i]);
    	sprintf(&hashString[i*2], "%02x", (unsigned int)hash[i+32]);
	}

	mpz_init_set_str(sk->s, hashString, 16);
	mpz_mod(sk->s, sk->s, pPrime);

	int size = get_size(&sk->s);
	char sbits[size];
	to_bits(sbits, &sk->s);

	mpz_inits(pk->A1, pk->A2, NULL);
	mul_scalar(&pk->A1, &pk->A2, &B1, &B2, sbits, &size);
}

void sign_message(signature *sig, char *message, secretKey *sk, publicKey *pk)
{
	unsigned char hash[SHA512_DIGEST_LENGTH];

    SHA512_CTX sha512;
	SHA512_Init(&sha512);
    SHA512_Update(&sha512, sk->hsk, 32);
    SHA512_Update(&sha512, message, strlen(message));
    SHA512_Final(hash, &sha512);

    char hashString[SHA512_DIGEST_LENGTH];
	for(int i = 0; i < SHA512_DIGEST_LENGTH; i++)
	{
    	sprintf(&hashString[i*2], "%02x", (unsigned int)hash[i]);
	}

	mpz_t r;
	mpz_init_set_str(r, hashString, 16);
	mpz_mod(r, r, pPrime);

	int size = get_size(&r);
	char rbits[size];
	to_bits(rbits, &r);

	mpz_inits(sig->R1, sig->R2, sig->S, NULL);
	mul_scalar(&sig->R1, &sig->R2, &B1, &B2, rbits, &size);

	mpz_t hashMiMC;
	mpz_init(hashMiMC);

	mpz_t msg;
	mpz_init_set_str(msg, message, 10);

	size = 5;
	mpz_t arr[size];
	mpz_init_set(arr[0], sig->R1);
	mpz_init_set(arr[1], sig->R2);
	mpz_init_set(arr[2], pk->A1);
	mpz_init_set(arr[3], pk->A2);
	mpz_init_set(arr[4], msg);

	multi_mimc7(&hashMiMC, arr, &size);

	mpz_mul(sig->S, hashMiMC, sk->s);
	mpz_add(sig->S, sig->S, r);
	mpz_mod(sig->S,sig->S, order);

	for (int i = 0; i < 5; i++)
	{
		mpz_clear(arr[i]);
	}

	mpz_clears(msg, hashMiMC, r, NULL);
}

void clear_signature(signature *sig)
{
	mpz_clears(sig->R1, sig->R2, sig->S, NULL);
}

void clear_publickey(publicKey *pk)
{
	mpz_clears(pk->A1, pk->A2, NULL);
}

void clear_secretkey(secretKey *sk)
{
	mpz_clear(sk->s);
}

void init_public_parameters()
{
	mpz_init_set_str(pPrime, PRIMESTR, 10);
	mpz_init_set_str(order, ORDERSTR, 10);
	mpz_init_set_str(B1, B1STR, 10);
	mpz_init_set_str(B2, B2STR, 10);
	mpz_init_set_str(a, ASTR, 10);
	mpz_init_set_str(d, DSTR, 10);
}

void clear_public_parameters()
{
	mpz_clears(pPrime, order, B1, B2, a, d, NULL);
}