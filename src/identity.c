#include <string.h>
#include <stdint.h>
#include <inttypes.h>

#include <openssl/err.h>
#include <openssl/evp.h>

#include "identity.h"

#include <assert.h>

#include "base64.h"

static bool asn1_parse_integer(const unsigned char** asn1data_pos, long length, BIGNUM* bn_result)
{
    debug_printf("> asn1_parse_integer(%p, %li, %p)\n", *asn1data_pos, length, (void*) bn_result);
    bool result = true;
    ASN1_INTEGER* temp = ASN1_INTEGER_new();
    if (!d2i_ASN1_INTEGER(&temp, asn1data_pos, length))
    {
        fprintf(stderr, "d2i_ASN1_INTEGER() failed\n");
        result = false;
    }
    else
    {
        ASN1_INTEGER_to_BN(temp, bn_result);
    }
    ASN1_INTEGER_free(temp);

    debug_printf("< asn1_parse_integer(): %d\n", result);
    return result;
}

static bool asn1_parse(ts3_identity* identity, BIGNUM* x, BIGNUM* y, BIGNUM* z)
{
    debug_printf("> asn1_parse(%p, %p, %p, %p)\n", (void*) identity, (void*) x, (void*) y, (void*) z);
    assert(identity->asn1data != NULL);
    assert(identity->asn1data_len > 0);
    const unsigned char* asn1data_pos = identity->asn1data;
    long len, length = (long)identity->asn1data_len;
    int tag, xclass, ret;

    // SEQUENCE
    ret = ASN1_get_object(&asn1data_pos, &len, &tag, &xclass, length);
    if (ret & 0x80)
    {
        fprintf(stderr, "ASN1_get_object() failed\n");
        return false;
    }
    if (tag != V_ASN1_SEQUENCE)
    {
        fprintf(stderr, "(1) Invalid tag for ASN1: %d: %s\n", tag, ASN1_tag2str(tag));
        return false;
    }

    // BIT_STRING -- bitInfo, ignored for now
    ASN1_BIT_STRING* temp = ASN1_BIT_STRING_new();
    if (!d2i_ASN1_BIT_STRING(&temp, &asn1data_pos, length))
    {
        fprintf(stderr, "d2i_ASN1_BIT_STRING() failed\n");
        return false;
    }
    ASN1_BIT_STRING_free(temp);

    BIGNUM* ignored = BN_new();
    if (!asn1_parse_integer(&asn1data_pos, length, ignored))
    {
        fprintf(stderr, "asn1_parse_integer(ignored) failed\n");
        BN_free(ignored);
        return false;
    }
    BN_free(ignored);

    if (!asn1_parse_integer(&asn1data_pos, length, x))
    {
        fprintf(stderr, "asn1_parse_integer(x) failed\n");
        return false;
    }

    if (!asn1_parse_integer(&asn1data_pos, length, y))
    {
        fprintf(stderr, "asn1_parse_integer(y) failed\n");
        return false;
    }

    if (!asn1_parse_integer(&asn1data_pos, length, z))
    {
        fprintf(stderr, "asn1_parse_integer(z) failed\n");
        return false;
    }

    // sanity check, everything parsed?
    if (asn1data_pos != identity->asn1data + identity->asn1data_len)
    {
        debug_printf("  asn1_parse: dangling data: %c\n", *asn1data_pos);
    }

    debug_print("< asn1_parse(): 1\n");
    return true;
}

static bool ts3_xor(size_t a_len, const uint8_t* a, int aoffs,
                    size_t b_len, const uint8_t* b, int boffs,
                    size_t len,
                    size_t outBuf_len, uint8_t* outBuf, int outOffs)
{
    debug_printf("> ts3_xor(%" PRIu64 ", %p, %i, %" PRIu64 ", %p, %i, %" PRIu64 ", %" PRIu64 ", %p, %i)\n",
                 a_len, (void *) a, aoffs, b_len, (void *) b, boffs, len, outBuf_len, (void *) outBuf, outOffs);
    bool result = false;
    if (a_len >= len && b_len >= len && outBuf_len >= len)
    {
        for (size_t i = 0; i < len; i++)
        {
            outBuf[i + outOffs] = (uint8_t)(a[i + aoffs] ^ b[i + boffs]);
        }
        result = true;
    }
    debug_printf("< ts3_xor(): %u\n", result);
    return result;
}

static bool deobfuscate_key(size_t identityData_len, uint8_t identityData[identityData_len])
{
    debug_printf("> deobfuscate_key(%" PRIu64 ", %p)\n", identityData_len, identityData);
    bool result = true;
    uint8_t buffer[identityData_len];
    memcpy(buffer, identityData, identityData_len);

    uint8_t identityHash[SHA_DIGEST_LENGTH];
    {
        int nullIndex = -1;
        for (int i = 20; i < (int)identityData_len; i++)
        {
            if (buffer[i] == 0x0)
            {
                nullIndex = i - 20;
                break;
            }
        }
        debug_printf("  deobfuscate_key: nullIndex=%d\n", nullIndex);

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (ctx == NULL)
        {
            fprintf(stderr, "EVP_MD_CTX_new() failed\n");
            return false;
        }
        const EVP_MD* md = EVP_sha1();
        EVP_DigestInit(ctx, md);
        EVP_DigestUpdate(ctx, buffer + 20, nullIndex < 0 ? (int)identityData_len - 20 : nullIndex);
        EVP_DigestFinal(ctx, identityHash, NULL);
        EVP_MD_CTX_free(ctx);
        debug_print_hex("  deobfuscate_key: identityHash", identityHash, SHA_DIGEST_LENGTH);
    }

    if (!ts3_xor(identityData_len, buffer, 0,
                 20, identityHash, 0,
                 20,
                 identityData_len, buffer, 0))
    {
        fprintf(stderr, "xor() failed\n");
        result = false;
    }
    debug_print_hex("  deobfuscate_key: round 1", buffer, identityData_len);

    if (!ts3_xor(identityData_len, buffer, 0,
                 OBFUSCATION_KEY_LEN, OBFUSCATION_KEY, 0,
                 identityData_len > 100 ? 100 : identityData_len,
                 identityData_len, buffer, 0))
    {
        fprintf(stderr, "xor() failed\n");
        result = false;
    }
    debug_print_hex("  deobfuscate_key: round 2", buffer, identityData_len);

    bool null_found = false;
    for (size_t i = 0; i < identityData_len; i++)
    {
        if (buffer[i] == 0)
        {
            null_found = true;
            break;
        }
    }
    if (!null_found)
    {
        fprintf(stderr, "xor() failed, no null found\n");
        result = false;
    }

    if (result)
    {
        memcpy(identityData, buffer, identityData_len);
    }

    debug_printf("< deobfuscate_key(): %u\n", result);
    return result;
}

static bool obfuscate_key(size_t privkey_len, ts3_privkey_t privkey[privkey_len])
{
    debug_printf("> obfuscate_key(%" PRIu64 ", %p)\n", privkey_len, privkey);
    bool result = true;
    uint8_t buffer[privkey_len];
    memcpy(buffer, privkey, privkey_len);

    if (!ts3_xor(privkey_len, buffer, 0,
                 OBFUSCATION_KEY_LEN, OBFUSCATION_KEY, 0,
                 privkey_len > 100 ? 100 : privkey_len,
                 privkey_len, buffer, 0))
    {
        fprintf(stderr, "xor() failed\n");
        result = false;
    }
    debug_print_hex("  obfuscate_key: round 1", buffer, privkey_len);

    uint8_t identityHash[SHA_DIGEST_LENGTH];
    {
        int nullIndex = -1;
        for (int i = 20; i < (int)privkey_len; i++)
        {
            if (buffer[i] == 0x0)
            {
                nullIndex = i - 20;
                break;
            }
        }
        debug_printf("  obfuscate_key: nullIndex=%d\n", nullIndex);

        EVP_MD_CTX* ctx;
        ctx = EVP_MD_CTX_new();
        if (ctx == NULL)
        {
            fprintf(stderr, "EVP_MD_CTX_new() failed\n");
            return false;
        }

        const EVP_MD* md = EVP_sha1();
        EVP_DigestInit(ctx, md);
        EVP_DigestUpdate(ctx, buffer + 20, nullIndex < 0 ? (int)privkey_len - 20 : nullIndex);
        EVP_DigestFinal(ctx, identityHash, NULL);
        EVP_MD_CTX_free(ctx);
        debug_print_hex("  obfuscate_key: identityHash", identityHash, SHA_DIGEST_LENGTH);
    }

    if (!ts3_xor(privkey_len, buffer, 0,
                 20, identityHash, 0,
                 20,
                 privkey_len, buffer, 0))
    {
        fprintf(stderr, "xor() failed\n");
        result = false;
    }
    debug_print_hex("  obfuscate_key: round 2", buffer, privkey_len);

    if (result)
    {
        memcpy(privkey, buffer, privkey_len);
    }

    debug_printf("< obfuscate_key(): %u\n", result);
    return result;
}

static bool parse_counter_identity(char* id_str, ts3_identity* identity)
{
    debug_printf("> parse_counter_identity(%s, %p)\n", id_str, (void*) identity);
    char* temp = strdup(id_str);
    bool result = false;
    char* match = strchr(temp, 'V');
    if (match)
    {
        *match = '\0';
        identity->counter = strtoll(temp, NULL, 10);
        debug_printf("  counter: %" PRIu64 "\n", identity->counter);
        identity->encoded_identity = strdup(++match);
        debug_printf("  identity: %s\n", identity->encoded_identity);
        identity->encoded_identity_len = strlen(identity->encoded_identity);
        debug_printf("  identity_len: %" PRIu64 "\n", identity->encoded_identity_len);
        result = true;
    }
    free(temp);
    debug_printf("< parse_counter_identity(): %d\n", result);
    return result;
}

static bool parse_asn1_data(ts3_identity* identity)
{
    debug_printf("> parse_asn1_data(%p)\n", (void*) identity);
    assert(identity->encoded_identity != NULL);
    assert(identity->encoded_identity_len > 0);
    bool result = false;

    size_t bindata_len = base64_get_decode_length(identity->encoded_identity_len);
    uint8_t bindata[bindata_len];
    if (!base64_decode(identity->encoded_identity_len, (unsigned char*)identity->encoded_identity, &bindata_len,
                       bindata))
    {
        fprintf(stderr, "parse_asn1_data: base64_decode(1) failed\n");
        return result;
    }

    if (!deobfuscate_key(bindata_len, bindata))
    {
        fprintf(stderr, "parse_asn1_data: deobfuscate_key() failed\n");
        return result;
    }

    identity->asn1data_len = base64_get_decode_length(bindata_len);
    identity->asn1data = malloc(identity->asn1data_len);
    if (!base64_decode(bindata_len, bindata, &identity->asn1data_len, identity->asn1data))
    {
        fprintf(stderr, "parse_asn1_data: base64_decode(2) failed\n");
        return result;
    }
    debug_print_hex("  parse_asn1_data: asn1 data", identity->asn1data, identity->asn1data_len);
    result = true;

    debug_printf("< parse_asn1_data(): %d\n", result);
    return result;
}

bool create_pubkey(ts3_identity* identity, const BIGNUM* x, const BIGNUM* y)
{
    debug_printf("> create_pubkey(%p, %p, %p)\n", (void*) identity, (void*) x, (void*) y);
    uint8_t buffer[512];

    // start sequence
    buffer[0] = 0x30;

    // length of sequence, unknown yet
    buffer[1] = 0x00;

    // fixed bitstring
    buffer[2] = 0x03; // bitstring
    buffer[3] = 0x02; // length
    buffer[4] = 0x07; // value
    buffer[5] = 0x00;

    // fixed integer
    buffer[6] = 0x02; // integer
    buffer[7] = 0x01; // length
    buffer[8] = 0x20; // value

    // currently at index 9
    size_t buffer_pos = 9;
    {
        // write X
        uint8_t* temp = buffer + buffer_pos;
        ASN1_INTEGER* asn1 = ASN1_INTEGER_new();
        BN_to_ASN1_INTEGER(x, asn1);
        const int size = i2d_ASN1_INTEGER(asn1, &temp);
        debug_print_hex("  create_pubkey: asn1(x)", buffer + buffer_pos, size);
        debug_printf("  create_pubkey: size(x)=%i\n", size);
        buffer_pos += size;
        ASN1_INTEGER_free(asn1);
    }
    {
        // write X
        uint8_t* temp = buffer + buffer_pos;
        ASN1_INTEGER* asn1 = ASN1_INTEGER_new();
        BN_to_ASN1_INTEGER(y, asn1);
        const int size = i2d_ASN1_INTEGER(asn1, &temp);
        debug_print_hex("  create_pubkey: asn1(y)", buffer + buffer_pos, size);
        debug_printf("  create_pubkey: size(y)=%i\n", size);
        buffer_pos += size;
        ASN1_INTEGER_free(asn1);
    }

    // set length of sequence; excluding start tag and length itself
    buffer[1] = buffer_pos - 2;
    debug_printf("  create_pubkey: buffer_pos=%" PRIu64 "\n", buffer_pos);
    debug_printf("  create_pubkey: seq_length=%u\n", buffer[1]);

    identity->pubkey_len = base64_get_encode_length(buffer_pos);
    identity->pubkey = malloc(identity->pubkey_len + 1);
    bool result = base64_encode(buffer_pos, buffer, &identity->pubkey_len, identity->pubkey);
    debug_printf("< create_pubkey(): %d\n", result);
    return result;
}

bool create_privkey(ts3_identity* identity, const BIGNUM* x, const BIGNUM* y, const BIGNUM* z)
{
    debug_printf("> create_privkey(%p, %p, %p, %p)\n", (void*) identity, (void*) x, (void*) y, (void*) z);
    uint8_t buffer[512];

    // start sequence
    buffer[0] = 0x30;

    // length of sequence, unknown yet
    buffer[1] = 0x00;

    // fixed bitstring
    buffer[2] = 0x03;
    buffer[3] = 0x02;
    buffer[4] = 0x07;
    buffer[5] = 0x80;

    // fixed integer
    buffer[6] = 0x02;
    buffer[7] = 0x01;
    buffer[8] = 0x20;

    // currently at index 9
    size_t buffer_pos = 9;
    {
        // write x
        uint8_t* temp = buffer + buffer_pos;
        ASN1_INTEGER* asn1 = ASN1_INTEGER_new();
        BN_to_ASN1_INTEGER(x, asn1);
        const int size = i2d_ASN1_INTEGER(asn1, &temp);
        debug_print_hex("  create_privkey: asn1(x)", buffer + buffer_pos, size);
        debug_printf("  create_privkey: size(x)=%i\n", size);
        buffer_pos += size;
        ASN1_INTEGER_free(asn1);
    }
    {
        // write y
        uint8_t* temp = buffer + buffer_pos;
        ASN1_INTEGER* asn1 = ASN1_INTEGER_new();
        BN_to_ASN1_INTEGER(y, asn1);
        const int size = i2d_ASN1_INTEGER(asn1, &temp);
        debug_print_hex("  create_privkey: asn1(y)", buffer + buffer_pos, size);
        debug_printf("  create_privkey: size(y)=%i\n", size);
        buffer_pos += size;
        ASN1_INTEGER_free(asn1);
    }
    {
        // write z
        uint8_t* temp = buffer + buffer_pos;
        ASN1_INTEGER* asn1 = ASN1_INTEGER_new();
        BN_to_ASN1_INTEGER(z, asn1);
        const int size = i2d_ASN1_INTEGER(asn1, &temp);
        debug_print_hex("  create_privkey: asn1(z)", buffer + buffer_pos, size);
        debug_printf("  create_privkey: size(z)=%i\n", size);
        buffer_pos += size;
        ASN1_INTEGER_free(asn1);
    }

    // set length of sequence
    buffer[1] = buffer_pos - 2;
    debug_printf("  create_privkey: buffer_pos=%" PRIu64 "\n", buffer_pos);
    debug_printf("  create_pubkey: seq_length=%u\n", buffer[1]);

    identity->privkey_len = base64_get_encode_length(buffer_pos);
    identity->privkey = malloc(identity->privkey_len + 1);
    bool result = base64_encode(buffer_pos, buffer, &identity->privkey_len, identity->privkey);
    debug_printf("< create_privkey(): %d\n", result);
    return result;
}

bool create_uuid(ts3_identity* identity)
{
    debug_printf("> create_uuid(%p)\n", (void*) identity);
    assert(identity->pubkey != NULL);
    assert(identity->pubkey_len > 0);
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
    {
        fprintf(stderr, "EVP_MD_CTX_new() failed\n");
        return false;
    }
    const EVP_MD* md = EVP_sha1();
    uint8_t hash[SHA_DIGEST_LENGTH];

    EVP_DigestInit(ctx, md);
    EVP_DigestUpdate(ctx, identity->pubkey, identity->pubkey_len);
    EVP_DigestFinal(ctx, hash, NULL);
    EVP_MD_CTX_free(ctx);

    debug_print_hex("  create_uuid: hash", hash, SHA_DIGEST_LENGTH);

    identity->uuid_len = base64_get_encode_length(SHA_DIGEST_LENGTH);
    identity->uuid = malloc(identity->uuid_len + 1);
    bool result = base64_encode(SHA_DIGEST_LENGTH, hash, &identity->uuid_len, identity->uuid);
    debug_printf("< create_uuid(): %d\n", result);
    return result;
}


bool decode_identity(char* id_str, ts3_identity* identity)
{
    debug_printf("> parse_identity(%s, %p)\n", id_str, (void*) identity);
    if (!parse_counter_identity(id_str, identity)) return false;
    if (!parse_asn1_data(identity)) return false;

    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();
    BIGNUM* z = BN_new();
    if (!asn1_parse(identity, x, y, z))
    {
        fprintf(stderr, "asn1_parse() failed\n");
        unsigned long code;
        while ((code = ERR_get_error()))
        {
            char message[1024];
            ERR_error_string_n(code, message, sizeof(message));
            fprintf(stderr, "> %s\n", message);
        }
        BN_free(x);
        BN_free(y);
        BN_free(z);
        return false;
    }

    if (!create_privkey(identity, x, y, z))
    {
        BN_free(x);
        BN_free(y);
        BN_free(z);
        return false;
    }
    BN_free(z);

    if (!create_pubkey(identity, x, y))
    {
        BN_free(x);
        BN_free(y);
        return false;
    }
    BN_free(x);
    BN_free(y);
    if (!create_uuid(identity))
    {
        return false;
    }

    debug_printf("< parse_identity(): %d\n", true);
    return true;
}

char* encode_identity(ts3_identity* identity, size_t* encoded_len)
{
    debug_printf("> encode_identity(%p, %p)\n", (void*) identity, (void*) encoded_len);
    assert(identity->privkey != NULL);
    assert(identity->privkey_len > 0);
    if (!obfuscate_key(identity->privkey_len, identity->privkey))
    {
        fprintf(stderr, "obfuscate_key() failed\n");
        return NULL;
    }

    size_t obfuscated_len = base64_get_encode_length(identity->privkey_len);
    char* obfuscated = calloc(obfuscated_len + 1, sizeof(char));
    base64_encode(identity->privkey_len, identity->privkey, &obfuscated_len, (unsigned char*)obfuscated);
    debug_printf("  main: obfuscated=%s\n", obfuscated);
    *encoded_len = obfuscated_len;
    return obfuscated;
}

void free_identity(ts3_identity* identity)
{
    if (!identity)
    {
        return;
    }
    if (identity->encoded_identity)
    {
        free(identity->encoded_identity);
        identity->encoded_identity = NULL;
    }
    if (identity->pubkey)
    {
        free(identity->pubkey);
        identity->pubkey = NULL;
    }
    if (identity->privkey)
    {
        free(identity->privkey);
        identity->privkey = NULL;
    }
    if (identity->uuid)
    {
        free(identity->uuid);
        identity->uuid = NULL;
    }
    if (identity->asn1data)
    {
        free(identity->asn1data);
        identity->asn1data = NULL;
    }
}

uint8_t get_security_level(ts3_identity* identity)
{
    debug_printf("> get_security_level(%p)\n", (void*) identity);
    assert(identity->pubkey_len > 0);
    assert(identity->pubkey != NULL);
    assert(identity->counter > 0);
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
    EVP_DigestUpdate(ctx, identity->pubkey, identity->pubkey_len);
    char buffer[32];
    snprintf(buffer, 32, "%" PRIu64, identity->counter);
    EVP_DigestUpdate(ctx, buffer, strlen(buffer));
    uint32_t hash[SHA_DIGEST_LENGTH / 4];
    EVP_DigestFinal(ctx, (uint8_t*)hash, NULL);
    EVP_MD_CTX_free(ctx);

    debug_print_hex("  get_security_level: state", hash, SHA_DIGEST_LENGTH);
    const uint8_t result = leading_zero_bits(hash);
    debug_printf("< get_security_level(): %u\n", result);
    return result;
}
