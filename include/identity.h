#ifndef TS3_IDENTITY_H
#define TS3_IDENTITY_H

#include <stdbool.h>
#include <stdint.h>

#include "globals.h"
#include "openssl/ossl_typ.h"

typedef struct ts3_identity_t
{
    uint64_t counter;

    char* encoded_identity;
    size_t encoded_identity_len;

    ts3_uuid_t* uuid;
    size_t uuid_len;

    ts3_privkey_t* privkey;
    size_t privkey_len;

    ts3_pubkey_t* pubkey;
    size_t pubkey_len;

    uint8_t* asn1data;
    size_t asn1data_len;
} ts3_identity;

bool decode_identity(char* id_str, ts3_identity* identity);

char* encode_identity(ts3_identity* identity, size_t* encoded_len);

bool create_pubkey(ts3_identity* identity, const BIGNUM* x, const BIGNUM* y);

bool create_privkey(ts3_identity* identity, const BIGNUM* x, const BIGNUM* y, const BIGNUM* z);

bool create_uuid(ts3_identity* identity);

uint8_t get_security_level(ts3_identity* identity);

void free_identity(ts3_identity* identity);

#endif //TS3_IDENTITY_H
