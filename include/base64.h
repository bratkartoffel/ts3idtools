#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifndef TS3IDGEN_BASE64_H
#define TS3IDGEN_BASE64_H

size_t base64_get_decode_length(size_t len);

size_t base64_get_encode_length(size_t len);

bool base64_encode(size_t input_length, const uint8_t input[input_length],
                   size_t *output_length, uint8_t output[*output_length]);

bool base64_decode(size_t input_length, const unsigned char input[input_length],
                   size_t *output_length, uint8_t output[*output_length]);

#endif //TS3IDGEN_BASE64_H
