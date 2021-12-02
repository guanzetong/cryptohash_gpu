// Cryptohash

#include <wb.h>
#include <stdio.h>

#define NUM_CHAR 62
#define MAX_LEN 3

// CPU var
char *test;
uint8_t int_test[16];

// GPU constant memory
__constant__ uint32_t device_k[64];
__constant__ uint32_t device_r[64];
__constant__ uint32_t device_h_init[4];
__constant__ char device_charset[62];

// GPU functions

// leftrotate function definition
#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))

inline void to_bytes(uint32_t val, uint8_t *bytes)
{
    bytes[0] = (uint8_t) val;
    bytes[1] = (uint8_t) (val >> 8);
    bytes[2] = (uint8_t) (val >> 16);
    bytes[3] = (uint8_t) (val >> 24);
}

// HASH to uint8
void hash_to_int(char *charHash, uint8_t intHash[]){
    char tempChar[16][3];
    int j=0;
    while(j<16){
        tempChar[j][0] = charHash[j*2];
        tempChar[j][1] = charHash[j*2+1];
        tempChar[j][2] = '\0';
        ++j;
    }
    j = 0;
    while(j<16){
        sscanf(tempChar[j], "%x", (unsigned int*)(&(intHash[j])));
        ++j;
    }
}

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
__device__ void md5(uint8_t *password, size_t length, uint8_t *digest) {

    // These vars will contain the hash
    uint32_t h0, h1, h2, h3;
    uint32_t w[16];
    uint32_t a, b, c, d, i, f, g, temp;

    // Append the "1" bit; most significant bit is "first"
    password[length] = 0x80;

    // Store password to register
    for (i = 0; i < 14; i++) {
        w[i] = bytes_to_word(password + i*4);
    }

    // Append the length in bits at the end of the buffer.
    uint8_t length_bytes[4];
    word_to_bytes(length<<3, length_bytes);
    w[14] = bytes_to_word(length_bytes); // the lower 4 bytes
    // length>>29 == length*8>>32, but avoids overflow.
    word_to_bytes(length>>29, length_bytes);
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

// Password generator
__device__ void generate_password(size_t length, uint8_t *password, int id) {
    uint32_t current_word = id;
    for (int i = 0; i < length; i++) {
        password[length - 1 - i] = (uint8_t)device_charset[current_word % NUM_CHAR];
        current_word /= NUM_CHAR;
    }
    for (int i = length; i < 56; i++) {
        password[i] = 0;
    }
}

// Brute force
__global__ void brute_force(uint8_t *test_digest, size_t length, uint32_t max_num, uint8_t* found_flag, uint8_t *password_found, uint8_t *calc_digest, uint8_t *pwd, uint8_t *misflag, uint8_t *misj) {

    uint8_t digest[16]; // This var will store the calculated MD5 hash
    uint8_t mismatch = 0; // The result of comparison between target hash and calculated hash
    uint8_t password[56]; // The password for calculation

    int tid = blockDim.x * blockIdx.x + threadIdx.x;

    for (int i = 0; tid + i < max_num; i = i + blockDim.x * gridDim.x) {

        // Generate a password for MD5
        generate_password(length, password, tid + i);

        // int pwd_index = (tid + i)* 56;
        // for (int j = 0; j < 16; j++) {
        //     pwd[pwd_index + j] = password[j];
        // }

        // Invoke MD5
        md5(password, length, digest);


        int digest_index = (tid + i) * 16;
        for (int j = 0; j < 16; j++) {
            calc_digest[digest_index + j] = digest[j];
        }

        // Compare with the target hash
        mismatch = 0;
        for (int j = 0; j < 16; j++) {
            if (digest[j] != test_digest[j]) {
                mismatch = 1;
            }
        }
        misflag[tid + i] = mismatch;

        // If found the correct password, write to global memory
        if (mismatch == 0) {
            for (int j = 0; j < 56; j++) {
                password_found[j] = password[j];
            }
            *found_flag = 1;
        }

        
        int pwd_index = (tid + i)* 56;
        for (int j = 0; j < 56; j++) {
            pwd[pwd_index + j] = password[j];
        }

        __syncthreads();

        // Check if any thread has found the correct password
        // The found_flag is in global memory
        if (*found_flag == 1) {
            return;
        }
    }
    // return;
}


__global__ void get_md5(uint8_t *password, size_t length, uint8_t *digest) {
    md5(password, length, digest);
}

__global__ void gen_pwd(int length, int max_num, uint8_t *password) {//, int *id, char *char_d) {
    int tid = blockDim.x * blockIdx.x + threadIdx.x;
    // uint8_t local_password[56];
    for (int i = 0; i + tid < max_num; i = i + blockDim.x * gridDim.x) {
        uint32_t password_index = (tid + i) * 56;
        uint32_t id_index = tid + i;
        // id[id_index] = id_index;
        // char_d[id_index] = device_charset[id_index % NUM_CHAR];
        generate_password(length, password + password_index, id_index);

        // for (int j = 0; j < length; j++) {
        //     password[password_index + length - 1 - j] = device_charset[id_index % NUM_CHAR];
        //     id_index /= NUM_CHAR;
        // }
        // for (int j = length; j < 56; j++) {
        //     password[password_index + j] = 0;
        // }
    }
}

// int main(int argc, char **argv) {
//     // Check input parameters

//     if (argc < 2) {
//         printf("usage: %s 'stringhash'\n", argv[0]);
//         return 1;
//     }

//     int test_length;
//     test = argv[1];
//     test_length = strlen(test);
//     if(test_length > 50){
//         printf ("Invalid password. Exiting.\n");
//         exit(0);
//     }

//     // Prepare constants in contant memory
//     printf("Prepare constants in constant memory\n");

//     uint32_t host_k[64] = {
//         0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee ,
//         0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501 ,
//         0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be ,
//         0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821 ,
//         0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa ,
//         0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8 ,
//         0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed ,
//         0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a ,
//         0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c ,
//         0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70 ,
//         0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05 ,
//         0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665 ,
//         0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039 ,
//         0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1 ,
//         0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1 ,
//         0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 };

//     uint32_t host_r[64] =  {
//         7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
//         5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
//         4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
//         6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

//     uint32_t host_h_init[4] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};

//     const char* host_charset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

//     cudaMemcpyToSymbol(device_k, host_k, 64 * sizeof(uint32_t));
//     cudaMemcpyToSymbol(device_r, host_r, 64 * sizeof(uint32_t));
//     cudaMemcpyToSymbol(device_h_init, host_h_init, 4 * sizeof(uint32_t));
//     cudaMemcpyToSymbol(device_charset, host_charset, 62 * sizeof(char));

//     uint8_t *host_password;
//     uint8_t *host_digest;
//     // uint32_t *host_process;
//     // uint8_t *host_process_byte;
//     // uint8_t *host_local_password;

//     uint8_t *device_password;
//     uint8_t *device_digest;
//     // uint32_t *device_process;
//     // uint8_t *device_local_password;

//     host_password = (uint8_t *)malloc(56 * sizeof(uint8_t));
//     host_digest = (uint8_t *)malloc(16 * sizeof(uint8_t));
//     // host_process = (uint32_t *)malloc(16 * sizeof(uint32_t));
//     // host_process_byte = (uint8_t *)malloc(64 * sizeof(uint8_t));
//     // host_local_password = (uint8_t *)malloc(56 * sizeof(uint8_t));

//     printf("%d\n\n", test_length);

//     // *host_password = (uint8_t)*test;
//     for (int i = 0; i < test_length; i++) {
//         host_password[i] = test[i];
//         printf("%d\t", (char)host_password[i]);
//     }
//     for (int i = test_length; i < 56; i++) {
//         host_password[i] = 0;
//         printf("%d\t", host_password[i]);
//     }
//     printf("\n");
//     printf("\n");

//     cudaMalloc((void**)&device_password, 56 * sizeof(uint8_t));
//     cudaMalloc((void**)&device_digest, 16 * sizeof(uint8_t));
//     // cudaMalloc((void**)&device_process, 16 * sizeof(uint32_t));
//     // cudaMalloc((void**)&device_local_password, 56 * sizeof(uint8_t));

//     cudaMemcpy(device_password, host_password, 56 * sizeof(uint8_t), cudaMemcpyHostToDevice);

//     dim3 grid_dim(1,1,1);
//     dim3 block_dim(1,1,1);
//     get_md5<<<grid_dim, block_dim>>>(device_password, test_length, device_digest);//, device_process, device_local_password);

//     cudaMemcpy(host_digest, device_digest, 16 * sizeof(uint8_t), cudaMemcpyDeviceToHost);
//     // cudaMemcpy(host_process, device_process, 16 * sizeof(uint32_t), cudaMemcpyDeviceToHost);
//     // cudaMemcpy(host_local_password, device_local_password, 56 * sizeof(uint8_t), cudaMemcpyDeviceToHost);

//     printf("The MD5 of %s is", test);
//     for (int i = 0; i < 16; i++) {
//         printf("%x\t", host_digest[i]);
//     }
//     printf("\n");
//     printf("\n");

//     // for (int i = 0; i < 16; i++) {
//     //     to_bytes(host_process[i], host_process_byte + i * 4);
//     // }
//     // // printf("The processed password of %s is", test);
//     // for (int i = 0; i < 64; i++) {
//     //     printf("%d\t", host_process_byte[i]);
//     // }
//     // printf("\n");
//     // printf("\n");

//     // for (int i = 0; i < 56; i++) {
//     //     printf("%d\t", host_local_password[i]);
//     // }
//     // printf("\n");
//     // printf("\n");

//     cudaFree(device_password);
//     cudaFree(device_digest);
//     // cudaFree(device_process);

//     free(host_password);
//     free(host_digest);
//     // free(host_process);
// }

int main(int argc, char **argv) {

    // Check input parameters
    if (argc < 2) {
        printf("usage: %s 'stringhash'\n", argv[0]);
        return 1;
    }
    test = argv[1];
    if(strlen(test) != 32){
        printf ("Invalid hash. Exiting.\n");
        exit(0);
    }

    printf("Convert hash to uint8\n");
    hash_to_int(test, int_test);  // Convert target hash to uint8_t
    for (int i = 0; i < 32; i++) {
        printf("%c", test[i]);
    }
    printf("\n");

    for (int i = 0; i < 16; i++) {
        printf("%x", int_test[i]);
    }
    printf("\n");

    printf("Declare variables\n");
    uint8_t *host_found_flag;
    uint8_t *host_password_found;
    uint8_t *host_calc_digest;
    uint8_t *host_pwd;
    uint8_t *host_misflag;
    uint8_t *host_misj;

    uint8_t *device_found_flag;
    uint8_t *device_test_digest;
    uint8_t *device_password_found;
    uint8_t *device_calc_digest;
    uint8_t *device_pwd;
    uint8_t *device_misflag;
    uint8_t *device_misj;

    printf("Allocate host memory\n");
    host_found_flag = (uint8_t *)malloc(sizeof(uint8_t));
    host_password_found = (uint8_t *)malloc(56 * sizeof(uint8_t));
    host_calc_digest = (uint8_t *)malloc(16 * NUM_CHAR * sizeof(uint8_t));
    host_pwd = (uint8_t *)malloc(56 * NUM_CHAR * sizeof(uint8_t));
    host_misflag = (uint8_t *)malloc(NUM_CHAR * sizeof(uint8_t));
    host_misj = (uint8_t *)malloc(NUM_CHAR * sizeof(uint8_t));

    printf("Allocate device global memory\n");
    cudaMalloc((void **)&device_test_digest, 16 * sizeof(uint8_t));
    cudaMalloc((void **)&device_found_flag, sizeof(uint8_t));
    cudaMalloc((void **)&device_password_found, 56 * sizeof(uint8_t));
    cudaMalloc((void **)&device_calc_digest, 16 * NUM_CHAR * sizeof(uint8_t));
    cudaMalloc((void **)&device_pwd, 56 * NUM_CHAR * sizeof(uint8_t));
    cudaMalloc((void **)&device_misflag, NUM_CHAR * sizeof(uint8_t));
    cudaMalloc((void **)&device_misj, NUM_CHAR * sizeof(uint8_t));

    printf("Copy from host to device memory\n");
    *host_found_flag = 0;
    for (int i = 0; i < 56; i++) {
        host_password_found[i] = 0;
    }
    cudaMemcpy(device_found_flag, host_found_flag, sizeof(uint8_t), cudaMemcpyHostToDevice);
    cudaMemcpy(device_password_found, host_password_found, 56 * sizeof(uint8_t), cudaMemcpyHostToDevice);
    cudaMemcpy(device_test_digest, int_test, 16 * sizeof(uint8_t), cudaMemcpyHostToDevice);

    printf("Prepare constants in device constant memory\n");

    uint32_t host_k[64] = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee ,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501 ,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be ,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821 ,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa ,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8 ,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed ,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a ,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c ,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70 ,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05 ,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665 ,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039 ,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1 ,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1 ,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 };

    uint32_t host_r[64] =  {
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

    uint32_t host_h_init[4] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};

    const char* host_charset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

    cudaMemcpyToSymbol(device_k, host_k, 64 * sizeof(uint32_t));
    cudaMemcpyToSymbol(device_r, host_r, 64 * sizeof(uint32_t));
    cudaMemcpyToSymbol(device_h_init, host_h_init, 4 * sizeof(uint32_t));
    cudaMemcpyToSymbol(device_charset, host_charset, 62 * sizeof(char));


    printf("Scan from length = 1 to %d\n", MAX_LEN);
    int max_num = 1;
    for (int i = 0; i < MAX_LEN; i++) {
        max_num *= NUM_CHAR;
        size_t password_length = i + 1;

        printf("Password length: %d\n", i+1);

        // Grid dimensions and block dimensions
        dim3 block_dim(256, 1, 1);
        dim3 grid_dim(256, 1, 1);
        
        // Invoke brute_force
        printf("Brute force start\n");
        brute_force<<<grid_dim, block_dim>>>(device_test_digest, password_length, max_num, device_found_flag, device_password_found, device_calc_digest, device_pwd, device_misflag, device_misj);
        cudaDeviceSynchronize();

        cudaMemcpy(host_calc_digest, device_calc_digest, 16 * NUM_CHAR * sizeof(uint8_t), cudaMemcpyDeviceToHost);
        for (int j = 0; j < NUM_CHAR; j++) {
            for(int k = 0; k < 16; k++) {
                printf("%x", host_calc_digest[j * 16 + k]);
            }
            printf("\n");
        }

        cudaMemcpy(host_pwd, device_pwd, 56 * NUM_CHAR * sizeof(uint8_t), cudaMemcpyDeviceToHost);
        for (int j = 0; j < NUM_CHAR; j++) {
            for(int k = 0; k < 56; k++) {
                printf("%x", host_pwd[j * 56 + k]);
            }
            printf("\n");
        }

        cudaMemcpy(host_misflag, device_misflag, NUM_CHAR * sizeof(uint8_t), cudaMemcpyDeviceToHost);
        cudaMemcpy(host_misj, device_misj, NUM_CHAR * sizeof(uint8_t), cudaMemcpyDeviceToHost);
        for (int j = 0; j < NUM_CHAR; j++) {
            printf("%d\t%d\n", host_misflag[j], host_misj[j]);
        }

        // Read result
        cudaMemcpy(host_found_flag, device_found_flag, sizeof(uint8_t), cudaMemcpyDeviceToHost);
        printf("Found flag:%d\n", *host_found_flag);
        printf("Brute force end\n");
        if (*host_found_flag == 1) {
            cudaMemcpy(host_password_found, device_password_found, 56 * sizeof(uint8_t), cudaMemcpyDeviceToHost);
            printf("The password is: ");
            for (int j = 0; j < i + 1; j++) {
                printf("%c", host_password_found[j]);
            }
            printf("\n");
            break;
        }

        // Scan through all given length
        if (i == MAX_LEN-1) {
            printf("The password is not found.\n");
        }
    }

    printf("Free host and device memory\n");
    cudaFree(device_test_digest);
    cudaFree(device_found_flag);
    cudaFree(device_calc_digest);
    cudaFree(device_pwd);
    cudaFree(device_misflag);
    cudaFree(device_misj);

    free(host_found_flag);
    free(host_password_found);
    free(host_calc_digest);
    free(host_pwd);
    free(host_misflag);
    free(host_misj);

    return 0;
}

// int main(int argc, char **argv) {
//     // Check input parameters
//     if (argc < 2) {
//         printf("usage: %s 'password_length'\n", argv[0]);
//         return 1;
//     }

//     char length_str;
//     size_t length;
//     length_str = *argv[1];
//     if(length_str < 49 || length_str > 57){
//         printf ("Invalid password_length. Exiting.\n");
//         exit(0);
//     }
//     length = (size_t)(length_str - 48);

//     const char* host_charset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
//     cudaMemcpyToSymbol(device_charset, host_charset, 62 * sizeof(char));

//     // length = 1;
//     int max_num = 1;
//     for (int i = 0; i < length; i++) {
//         max_num = max_num * NUM_CHAR;
//     }
//     printf("Number of combiantions: %d\n", max_num);

//     uint8_t *host_password;

//     uint8_t *device_password;

//     host_password = (uint8_t*)malloc(max_num * 56 * sizeof(uint8_t));

//     cudaMalloc((void **)&device_password, max_num * 56 * sizeof(uint8_t));

//     dim3 block_dim(256, 1, 1);
//     dim3 grid_dim(256, 1, 1);

//     gen_pwd<<<grid_dim, block_dim>>>(length, max_num, device_password);

//     cudaMemcpy(host_password, device_password, max_num * 56 * sizeof(uint8_t), cudaMemcpyDeviceToHost);

//     for (int i = 0; i < max_num; i++) {
//         for (int j = 0; j < 56; j++) {
//             printf("%x", host_password[i*56+j]);
//         }
//         printf("\n");
//     }

//     cudaFree(device_password);
//     free(host_password);

//     return 0;
// }