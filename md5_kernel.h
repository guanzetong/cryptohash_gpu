#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct password_t{
    char word[56];
    size_t length;
} password;

__device__ uint32_t bytes_to_word(uint8_t *bytes);

__device__ void word_to_bytes(uint32_t word, uint8_t *bytes);

__device__ void md5(password *pwd, uint8_t *digest);