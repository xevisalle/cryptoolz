#include "lib/cryptoolz.h"

int main()
{
	// we initialize the public BN128 and Baby JubJub parameters
	init_public_parameters();

	// generate keypair
	secretKey sk;
	sk.sk = "00112233445566778899";
	
	publicKey pk;
	generate_keypair(&pk, &sk);

	printf("KEYPAIR GENERATION\n");
	gmp_printf("A1: %Zd \n", pk.A1);
	gmp_printf("A2: %Zd \n", pk.A2);

	// sign message
	char *message = "1234";
	signature sig;
	sign_message(&sig, message, &sk, &pk);

	printf("\nSIGN MESSAGE\n");
	printf("msg: %s \n", message);
	gmp_printf("R1: %Zd \n", sig.R1);
	gmp_printf("R2: %Zd \n", sig.R2);
	gmp_printf("S: %Zd \n", sig.S);

	// verify signature
	printf("\nVERIFY SIGNATURE\n");
	int isVerified = verify_signature(&sig, message, &pk);
	printf("Is verified: %d\n", isVerified);

	// we clear the public parameters to avoid memory leaks
	clear_public_parameters();

	// we clear the structs we used
	clear_signature(&sig);
	clear_publickey(&pk);
	clear_secretkey(&sk);

	return 0;
}