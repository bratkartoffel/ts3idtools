#ifndef TS3IDTOOLS_BASE64_H
#define TS3IDTOOLS_BASE64_H

#include <stdint.h>

size_t base64_get_decode_length(size_t len);

size_t base64_get_encode_length(size_t len);

bool base64_encode(size_t input_length, const unsigned char input[input_length],
                   size_t *output_length, unsigned char output[*output_length]);

bool base64_decode(size_t input_length, const unsigned char input[input_length],
                   size_t *output_length, unsigned char output[*output_length]);

#endif //TS3IDTOOLS_BASE64_H
