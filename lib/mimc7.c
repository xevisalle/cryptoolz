
void mimc7(mpz_t *hashOut, mpz_t *x_in, mpz_t *k)
{
	char buff[2048];
	FILE *cnst;
	cnst = fopen("lib/constants.txt", "r");

	mpz_t c[NROUNDS];
	for (int i = 0; i < NROUNDS; i++)
	{
		mpz_init(c[i]);
		fgets(buff, sizeof buff, cnst);
		mpz_set_str(c[i], buff, 10);
	}

	fclose(cnst);

	mpz_t t, r;
	mpz_init(t);
	mpz_init(r);

	for (int i = 0; i < NROUNDS; i++)
	{
		if (i == 0) mpz_add(t, *k, *x_in);
		else
		{
			mpz_add(t, *k, r);
			mpz_add(t, t, c[i]);
		}

		mpz_mod(t, t, pPrime);
		mpz_pow_ui(r, t, 7);
		mpz_mod(r, r, pPrime);
	}

	mpz_add(*hashOut, r, *k);
	mpz_mod(*hashOut, *hashOut, pPrime);

	mpz_clears(t, r, NULL);
	
	for (int i = 0; i < NROUNDS; i++)
	{
		mpz_clear(c[i]);
	}
}

void multi_mimc7(mpz_t *hash, mpz_t *arr, int *size)
{
	mpz_t k;
	mpz_init(k);

	for (int i = 0; i < *size; i++)
	{
		mimc7(hash, &arr[i], &k);
		mpz_add(k, arr[i], k);
		mpz_add(k, *hash, k);
		mpz_mod(k, k, pPrime);
	}

	mpz_set(*hash, k);
	mpz_clear(k);
}