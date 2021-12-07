#include "md5_kernel.cu"

#define NUM_CHAR 26

__constant__ password device_seq[20];
__constant__ char device_charset[26];

// Compare calculated digest with test digest
__device__ inline int compare_digest(uint8_t *calc_digest, uint8_t *test_digest) {
    int mismatch = 0;
    for (int j = 0; j < 16; j++) {
        if (calc_digest[j] != test_digest[j]) {
            mismatch = 1;
        }
    }
    return mismatch;
}

// Mutate dictionary content
__device__ void mutate_dict(int z, password *original, password *mutated) {
    memcpy(mutated, original, sizeof(password));
    if(z == -1){
    } else if (z==0){
        /* First letter uppercase */
        if ((*mutated).word[0] >= 'a' && (*mutated).word[0] <= 'z')
            (*mutated).word[0] +='A'-'a';
    } else if (z==1){
        /* Last letter uppercase */
        size_t len = (*mutated).length;
        if ((*mutated).word[len-1] >= 'a' && (*mutated).word[len-1] <= 'z')
            (*mutated).word[len-1] += 'A'-'a';
    } else if (z>=2 && z<=11){
        /* Add one digit to end
         * iterator: z-2    */
        size_t len = (*mutated).length;
        (*mutated).word[len] = '0' + z-2;
        (*mutated).length += 1;
    } else if (z>=12 && z<=111){
        /* Add sequence of numbers at end; e.g. 1234, 84, 1999 */
        // 0 to 99
        // iterator: z-12
        size_t len = (*mutated).length;
        (*mutated).word[len] = '0' + ((z-12)/10)%10;
        (*mutated).word[len+1] = '0' + (z-12)%10;
        (*mutated).length += 2;
    } else if (z>=112 && z<=231){
        // 1900 to 2020
        // iterator: z + (1900-112)
        size_t len = (*mutated).length;
        (*mutated).word[len] = '0' + ((z+1900-112)/1000)%10;
        (*mutated).word[len+1] = '0' + ((z+1900-112)/100)%10;
        (*mutated).word[len+2] = '0' + ((z+1900-112)/10)%10;
        (*mutated).word[len+3] = '0' + (z+1900-112)%10;
        (*mutated).length += 4;
    } else if (z>=232 && z<=251){
        // Other common sequences
        // iterator: z-232
        //sprintf(&temp,"%s",sequences[z-252]);
        size_t len = (*mutated).length;
        memcpy(&((*mutated).word[len]),device_seq[z-232].word,device_seq[z-232].length);
        (*mutated).length = len + device_seq[z-232].length;
    }
}

// Dictionary attack

__global__ void dict_attack(uint8_t *test_digest, password *pwd_dict, uint32_t max_num, password *password_found, volatile bool *found_flag) {
    uint8_t digest[16]; // This var will store the calculated MD5 hash
    uint8_t mismatch = 0; // The result of comparison between target hash and calculated hash
    password mutated_pwd;

    int tid = blockDim.x * blockIdx.x + threadIdx.x;

    volatile __shared__ bool shared_found_flag;

    // Each block use 1 thread to check found flag
    if (threadIdx.x == 0) {
        shared_found_flag = *found_flag;
    }

    __syncthreads();

    for (int i = 0; tid + i < max_num; i = i + blockDim.x * gridDim.x) {
        for (int z = -1; z < 252; z++) {

            // Check if the password has been found
            if (shared_found_flag) {
                return;
            }

            // Mutate dictionary contents
            mutate_dict(z, &(pwd_dict[tid + i]), &mutated_pwd);

            // Invoke MD5
            md5(&mutated_pwd, digest);

            // Compare with the target hash
            mismatch = compare_digest(digest, test_digest);

            // If found the correct password, write to global memory
            if (mismatch == 0) {
                memcpy(password_found, &mutated_pwd, sizeof(password));
                shared_found_flag = true;
                *found_flag = true;
            }

            // Each block update shared_found_flag according to global found flag
            if (threadIdx.x == 0) {
                shared_found_flag = *found_flag;
            }
        }
    }
}

// Brute force
__global__ void brute_force(uint8_t *test_digest, size_t try_length, uint32_t max_num, volatile bool *found_flag, password *pwd_found) {

    uint8_t digest[16]; // This var will store the calculated MD5 hash
    int mismatch = 0; // The result of comparison between target hash and calculated hash
    password pwd;

    int tid = blockDim.x * blockIdx.x + threadIdx.x;

    volatile __shared__ bool shared_found_flag;

    // Each block use 1 thread to check found flag
    if (threadIdx.x == 0) {
        shared_found_flag = *found_flag;
    }

    __syncthreads();
    
    for (int i = 0; tid + i < max_num; i = i + blockDim.x * gridDim.x) {

        // Check if the password has been found
        if (shared_found_flag) {
            return;
        }

        // Generate a password
        memset(&pwd, 0, sizeof(password));
        pwd.length = try_length;
        int current_word = tid + i;
        for (int j = 0; j < try_length; j++) {
            pwd.word[try_length - 1 - j] = device_charset[current_word % NUM_CHAR];
            current_word /= NUM_CHAR;
        }

        // Invoke MD5
        md5(&pwd, digest);

        // Compare with the target hash
        mismatch = compare_digest(digest, test_digest);

        // If found the correct password, write to global memory
        if (mismatch == 0) {
            memcpy(pwd_found, &pwd, sizeof(password));
            shared_found_flag = true;
            *found_flag = true;
        }

        // Each block update shared_found_flag according to global found flag
        if (threadIdx.x == 0) {
            shared_found_flag = *found_flag;
        }
    }
}
