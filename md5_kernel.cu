
// leftrotate function definition
#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))

typedef struct password_t{
    char word[56];
    size_t length;
} password;

// GPU constant memory
__constant__ uint32_t device_k[64];
__constant__ uint32_t device_r[64];
__constant__ uint32_t device_h_init[4];

// Convert 4 bytes(uint8_t) to 1 word(uint32_t)
__device__ uint32_t bytes_to_word(uint8_t *bytes)
{
    uint32_t word =  (uint32_t) bytes[0]
                  | ((uint32_t) bytes[1] << 8)
                  | ((uint32_t) bytes[2] << 16)
                  | ((uint32_t) bytes[3] << 24);
    return word;
}

// Convert 1 word(uint32_t) to 4 bytes(uint8_t)
__device__ void word_to_bytes(uint32_t word, uint8_t *bytes)
{
    bytes[0] = (uint8_t) word;
    bytes[1] = (uint8_t) (word >> 8);
    bytes[2] = (uint8_t) (word >> 16);
    bytes[3] = (uint8_t) (word >> 24);
}

// MD5
__device__ void md5(password *pwd, uint8_t *digest) {

    // These vars will contain the hash
    uint32_t h0, h1, h2, h3;
    uint32_t w[16];
    uint32_t a, b, c, d, i, f, g, temp;

    size_t init_len = pwd->length;
    uint8_t *msg = (uint8_t *)pwd->word;

    // Append the "1" bit; most significant bit is "first"
    msg[init_len] = 0x80;

    // Store password to register
    for (i = 0; i < 14; i++) {
        w[i] = bytes_to_word(msg + i*4);
    }

    // Append the length in bits at the end of the buffer.
    uint8_t length_bytes[4];
    word_to_bytes(init_len<<3, length_bytes);
    w[14] = bytes_to_word(length_bytes); // the lower 4 bytes
    // length>>29 == length*8>>32, but avoids overflow.
    word_to_bytes(init_len>>29, length_bytes);
    w[15] = bytes_to_word(length_bytes); // the higher 4 bytes

    // Initialize variables - simple count in nibbles:
    h0 = device_h_init[0];
    h1 = device_h_init[1];
    h2 = device_h_init[2];
    h3 = device_h_init[3];

    // Initialize hash value for this chunk:
    a = h0;
    b = h1;
    c = h2;
    d = h3;

    // Main loop:
    for(i = 0; i<64; i++) {

        if (i < 16) {
            f = (b & c) | ((~b) & d);
            g = i;
        } else if (i < 32) {
            f = (d & b) | ((~d) & c);
            g = (5*i + 1) % 16;
        } else if (i < 48) {
            f = b ^ c ^ d;
            g = (3*i + 5) % 16;
        } else {
            f = c ^ (b | (~d));
            g = (7*i) % 16;
        }

        temp = d;
        d = c;
        c = b;
        b = b + LEFTROTATE((a + f + device_k[i] + w[g]), device_r[i]);
        a = temp;

    }

    // Add this chunk's hash to result so far:
    h0 += a;
    h1 += b;
    h2 += c;
    h3 += d;

    //var char digest[16] := h0 append h1 append h2 append h3 //(Output is in little-endian)
    word_to_bytes(h0, digest);
    word_to_bytes(h1, digest + 4);
    word_to_bytes(h2, digest + 8);
    word_to_bytes(h3, digest + 12);
}
