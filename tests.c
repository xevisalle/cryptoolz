#include "lib/cryptoolz.h"

#define RESET "\033[0m"
#define RED "\033[31m"
#define GREEN "\033[32m"

int test1()
{
	secretKey sk;
	sk.sk = "00112233445566778899";
	
	publicKey pk;
	generate_keypair(&pk, &sk);

	char *message = "1234";
	
	signature sig;
	sign_message(&sig, message, &sk, &pk);

	int verified = verify_signature(&sig, message, &pk);
	return verified;
}

int test2()
{
	secretKey sk;
	sk.sk = "00112233445566778899";
	
	publicKey pk;
	generate_keypair(&pk, &sk);

	char *message = "1234";
	
	signature sig;
	sign_message(&sig, message, &sk, &pk);

	char *fakeMessage = "5678";

	int verified = !verify_signature(&sig, fakeMessage, &pk);
	return verified;
}

int test3()
{
	secretKey sk;
	sk.sk = "00112233445566778899";
	
	publicKey pk;
	generate_keypair(&pk, &sk);

	char *message = "1234";
	
	signature sig;
	sign_message(&sig, message, &sk, &pk);

	mpz_set_str(sig.S, "123456789", 10);

 	int verified = !verify_signature(&sig, message, &pk);
	return verified;
}

int test4()
{
	secretKey sk;
	sk.sk = "00112233445566778899";
	
	publicKey pk;
	generate_keypair(&pk, &sk);

	char *message = "1234";
	
	signature sig;
	sign_message(&sig, message, &sk, &pk);

	mpz_set_str(pk.A1, "123456789", 10);

	int verified = !verify_signature(&sig, message, &pk);
	return verified;
}

int test5()
{
	mpz_t hash, x_in, k;
	mpz_inits(hash, x_in, k, NULL);
	mpz_set_str(x_in, "0011223344", 10);
	mpz_set_str(k, "1234", 10);
	mimc7(&hash, &x_in, &k);

	return 1;
}

int test6()
{
	int size = 4;
	mpz_t hash, arr[size];
	mpz_init(hash);

	for (int i = 0; i < size; i++)
	{
		mpz_init(arr[i]);
		mpz_set_str(arr[i], "0011223344", 10);
	}

	multi_mimc7(&hash, arr, &size);

	return 1;
}

int main()
{
	// we initialize the public BN128 and Baby JubJub parameters
	init_public_parameters();

	printf("Test 1: EdDSA - Generate keys, sign a message and verify: ");
	if (test1()) printf(GREEN "PASSED\n" RESET);
	else printf(RED "NOT PASSED\n" RESET);

	printf("Test 2: EdDSA - Generate keys, sign a message and verify a fake message: ");
	if (test2()) printf(GREEN "PASSED\n" RESET);
	else printf(RED "NOT PASSED\n" RESET);

	printf("Test 3: EdDSA - Generate keys, sign a message and verify a fake signature: ");
	if (test3()) printf(GREEN "PASSED\n" RESET);
	else printf(RED "NOT PASSED\n" RESET);

	printf("Test 4: EdDSA - Generate keys, sign a message and verify using a fake public key: ");
	if (test4()) printf(GREEN "PASSED\n" RESET);
	else printf(RED "NOT PASSED\n" RESET);

	printf("Test 5: MiMC7 - Hash a value with no exceptions: ");
	if (test5()) printf(GREEN "PASSED\n" RESET);
	else printf(RED "NOT PASSED\n" RESET);

	printf("Test 6: MiMC7 - Hash an array of values with no exceptions: ");
	if (test6()) printf(GREEN "PASSED\n" RESET);
	else printf(RED "NOT PASSED\n" RESET);

	// we clear the public parameters to avoid memory leaks
	clear_public_parameters();

	return 0;
}