#include "globals.h"
#include "base64.h"

#include <inttypes.h>
#include <openssl/evp.h>

size_t base64_get_decode_length(size_t len) {
    return 3 * len / 4;
}

size_t base64_get_encode_length(size_t len) {
    return 4 * ((len + 2) / 3);
}

bool base64_encode(size_t input_length, const uint8_t input[input_length],
                   size_t *output_length, uint8_t output[*output_length]) {
    debug_printf("> base64_encode(%" PRIu64 ", %p, %" PRIu64 ", %p)\n",
                 input_length, input, *output_length, output);
    *output_length = EVP_EncodeBlock(output, input, input_length);
    debug_printf("< base64_encode(-, -, %" PRIu64 ", -): 1\n", *output_length);
    return true;
}

bool base64_decode(size_t input_length, const unsigned char input[input_length],
                   size_t *output_length, uint8_t output[*output_length]) {
    debug_printf("> base64_decode(%" PRIu64 ", %p, %" PRIu64 ", %p)\n",
                 input_length, input, *output_length, output);
    size_t length = input_length;
    for (size_t i = length - 1; i > 0; i--) {
        if (input[i] == 0) {
            length--;
        } else {
            break;
        }
    }
    debug_printf("  base64_decode: length=%" PRIu64 "\n", length);
    int result = EVP_DecodeBlock(output, input, length);
    if (result != -1) {
        *output_length = result;
    }
    debug_printf("< base64_decode(-, -, %" PRIu64 ", -): %u\n", *output_length, result != 1);
    return result != -1;
}
