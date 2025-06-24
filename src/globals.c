#include "globals.h"
#include "base64.h"

bool debug = false;

size_t append_counter(uint8_t data[SHA1_MSG_SIZE], size_t length, uint64_t value)
{
    // no debug logging, extremely performance sensitive!
    size_t result;
    if (value > 9999999999999999999UL)
    {
        result = 20;
    }
    else if (value > 999999999999999999UL)
    {
        result = 19;
    }
    else if (value > 99999999999999999UL)
    {
        result = 18;
    }
    else if (value > 9999999999999999UL)
    {
        result = 17;
    }
    else if (value > 999999999999999UL)
    {
        result = 16;
    }
    else if (value > 99999999999999UL)
    {
        result = 15;
    }
    else if (value > 9999999999999UL)
    {
        result = 14;
    }
    else if (value > 999999999999UL)
    {
        result = 13;
    }
    else if (value > 99999999999UL)
    {
        result = 12;
    }
    else if (value > 9999999999UL)
    {
        result = 11;
    }
    else if (value > 999999999UL)
    {
        result = 10;
    }
    else if (value > 99999999UL)
    {
        result = 9;
    }
    else if (value > 9999999UL)
    {
        result = 8;
    }
    else if (value > 999999UL)
    {
        result = 7;
    }
    else if (value > 99999UL)
    {
        result = 6;
    }
    else if (value > 9999UL)
    {
        result = 5;
    }
    else if (value > 999UL)
    {
        result = 4;
    }
    else if (value > 99UL)
    {
        result = 3;
    }
    else if (value > 9UL)
    {
        result = 2;
    }
    else
    {
        result = 1;
    }

    for (uint8_t i = result - 1; i > 0; i--)
    {
        data[length + i] = (0x30 + (value % 10));
        value /= 10;
    }
    data[length] = (0x30 + value);
    return result + length;
}

size_t increment_counter(uint8_t data[SHA1_MSG_SIZE], size_t pubkey_length, size_t complete_length)
{
    uint8_t* start_counter = data + pubkey_length;
    uint8_t* end_counter = data + complete_length;
    for (uint8_t* pos = end_counter - 1; pos >= start_counter; pos--)
    {
        if (*pos < '9')
        {
            *pos = *pos + 1;
            return complete_length;
        }
        *pos = '0';
    }
    *start_counter = '1';
    *end_counter = '0';
    return complete_length + 1;
}

uint8_t leading_zero_bits(uint32_t hash[5])
{
    if (hash[0] == 0)
    {
        if (hash[1] == 0)
        {
            if (hash[2] == 0)
            {
                if (hash[3] == 0)
                {
                    if (hash[4] == 0)
                    {
                        return 160;
                    }
                    return 128 + __builtin_ctz(hash[4]);
                }
                return 96 + __builtin_ctz(hash[3]);
            }
            return 64 + __builtin_ctz(hash[2]);
        }
        return 32 + __builtin_ctz(hash[1]);
    }
    return __builtin_ctz(hash[0]);
}

#ifndef __aarch64__

#include <cpuid.h>
bool supports_sha_ni()
{
    unsigned int CPUInfo[4];
    __cpuid(0, CPUInfo[0], CPUInfo[1], CPUInfo[2], CPUInfo[3]);
    if (CPUInfo[0] < 7)
        return 0;

    __cpuid_count(7, 0, CPUInfo[0], CPUInfo[1], CPUInfo[2], CPUInfo[3]);
    return CPUInfo[1] & bit_SHA;
}

#else

bool supports_sha_ni()
{
    return false;
}

#endif

#ifndef HAVE_STRNDUP
char* strndup(const char* str, size_t maxlen)
{
    size_t len = strnlen(str, maxlen);
    char* copy = malloc(len + 1);
    if (copy != NULL)
    {
        memcpy(copy, str, len);
        copy[len] = '\0';
    }

    return copy;
}
#endif
