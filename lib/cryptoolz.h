#include <stdio.h>
#include <string.h>
#include <gmp.h>
#include <openssl/sha.h>

#define PRIMESTR "21888242871839275222246405745257275088548364400416034343698204186575808495617"
#define ORDERSTR "21888242871839275222246405745257275088614511777268538073601725287587578984328"
#define B1STR "5299619240641551281634865583518297030282874472190772894086521144482721001553"
#define B2STR "16950150798460657717958625567821834550301663161624707787222815936182638968203"
#define ASTR "168700"
#define DSTR "168696"
#define NROUNDS 91

mpz_t pPrime;
mpz_t order;
mpz_t B1;
mpz_t B2;
mpz_t a;
mpz_t d;

void mimc7(mpz_t *hashOut, mpz_t *x_in, mpz_t *k);
void multi_mimc7(mpz_t *hash, mpz_t *arr, int *size);

typedef struct PublicKey
{
    mpz_t A1;
    mpz_t A2;
} publicKey;

typedef struct SecretKey
{
    char *sk;
    char hsk[32];
    mpz_t s;
} secretKey;

typedef struct Signature
{
    mpz_t R1;
    mpz_t R2;
    mpz_t S;
} signature;

void clear_signature(signature *sig);
void clear_publickey(publicKey *pk);
void clear_secretkey(secretKey *sk);
void add(mpz_t *uOut, mpz_t *vOut, mpz_t *u1, mpz_t *v1, mpz_t *u2, mpz_t *v2);
void mul_scalar(mpz_t *mulOut1, mpz_t *mulOut2, mpz_t *doubledP10, mpz_t *doubledP20, char *exponent, int *size);
int get_size(mpz_t *val);
void to_bits(char *bits, mpz_t *val);
int verify_signature(signature *sig, char *message, publicKey *pk);
void generate_keypair(publicKey *pk, secretKey *sk);
void sign_message(signature *sig, char *message, secretKey *sk, publicKey *pk);
void init_public_parameters();

#include "eddsa.c"
#include "mimc7.c"