// Cryptohash

#include <wb.h>
#include "support.cu"
#include "cracker_kernel.cu"

#define BLOCK_SIZE 128
#define PWD_NUM_PER_THREAD 10
#define BRUTE_FORCE_MAX_LEN 5
#define MAX_GRID_SIZE 65536

// CPU var
char *test;
uint8_t int_test[16];
password seq[20];

// Initialize common seqences for dictionary mutations
void init_seq(){
    //seq = (password *)malloc(20*sizeof(password));
    memcpy(seq[0].word,"123", 3); seq[0].length = 3;
    memcpy(seq[1].word,"1234", 4); seq[1].length = 4;
    memcpy(seq[2].word,"12345", 5);   seq[2].length = 5;
    memcpy(seq[3].word,"123456", 6);   seq[3].length = 6;
    memcpy(seq[4].word,"1234567", 7);   seq[4].length = 7;
    memcpy(seq[5].word,"12345678", 8);   seq[5].length = 8;
    memcpy(seq[6].word,"123456789", 9);   seq[6].length = 9;
    memcpy(seq[7].word,"1234567890", 10);   seq[7].length = 10;
    memcpy(seq[8].word,"696969", 6);   seq[8].length = 6;
    memcpy(seq[9].word,"111111", 6);   seq[9].length = 6;
    memcpy(seq[10].word,"1111", 4);   seq[10].length = 4;
    memcpy(seq[11].word,"1212", 4);   seq[11].length = 4;
    memcpy(seq[12].word,"7777", 4);   seq[12].length = 4;
    memcpy(seq[13].word,"1004", 4);   seq[13].length = 4;
    memcpy(seq[14].word,"2000", 4);   seq[14].length = 4;
    memcpy(seq[15].word,"4444", 4);   seq[15].length = 4;
    memcpy(seq[16].word,"2222", 4);   seq[16].length = 4;
    memcpy(seq[17].word,"6969", 4);   seq[17].length = 4;
    memcpy(seq[18].word,"9999", 4);   seq[18].length = 4;
    memcpy(seq[19].word, "3333", 4);   seq[19].length = 4;
}

// Read dictionary
void readPwdFromFile(FILE *infile, password **pwd, unsigned int *numLines){

    unsigned int numberOfLines = 0;
    int ch;
    while (EOF != (ch=getc(infile))){
        if (ch=='\n'){
            ++numberOfLines;
            if(numberOfLines == (UINT_MAX/sizeof(char*)))
                break;
        }
    }
    rewind(infile);

    *pwd = (password*)malloc(numberOfLines*sizeof(password));
    if(*pwd == NULL){
        printf("\nERROR: Memory allocation did not complete successfully! Exiting.");
        exit(0);
    }

    char *line = NULL;
    size_t len = 0;
    int read_len = 0;
    unsigned int i=0;
    unsigned int toReduce = 0;
    while (i<numberOfLines) {
        read_len = getline(&line, &len, infile);
        if(read_len != -1){
            if(line[read_len-1] == '\n')    read_len = read_len - 1;
            if(line[read_len-1] == '\r')    read_len = read_len - 1;

            if(read_len > 45){
                //printf("Skipping (too big) - %s\n",line);
                ++toReduce;
            } else {
                // (*pwd)[i-toReduce] = (char*)malloc( (read_len+1)*sizeof(char));
                memcpy((*pwd)[i-toReduce].word,line,read_len);
                (*pwd)[i-toReduce].length = read_len;
                //printf("Pwd Read: %s, %d\n", (*pwd)[i], read_len);
              }
        } else {
            ++toReduce;
        }
        free(line);
        line = NULL;
        len = 0;
          i++;
    }
    *numLines = numberOfLines-toReduce;
    //passwd = &pwd;
}

// HASH to uint8
void hash_to_int(char *charHash, uint8_t intHash[]){
    char tempChar[16][3];
    int j = 0;
    while(j < 16){
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

    // Convert target hash to uint8_t
    hash_to_int(test, int_test);

    // Open dictionary file
    const char *filename = "plaintext/sorted_dict";
    FILE *infile;
    if ((infile = fopen (filename, "r")) == NULL){
        printf ("%s can't be opened\n", filename);
        exit(0);
    }

    init_seq();

    Timer totaltimer, filereadtimer, gpu_total_timer, md5_timer, dict_timer, brute_timer;
    startTime(&totaltimer);

    // Read file
    startTime(&filereadtimer);
    unsigned int numPwd;
    password *pwd;
    readPwdFromFile(infile, &pwd, &numPwd);
    printf("Total Dictionary Words: %d\n",numPwd);
    stopTime(&filereadtimer);
    printf("File read time: %f s\n", elapsedTime(filereadtimer));

    startTime(&gpu_total_timer);
    // Declare variables
    bool *host_found_flag;
    password *host_password_found;

    bool *device_found_flag;
    uint8_t *device_test_digest;
    password *device_password_found;
    password *device_pwd_dict;

    // Allocate host memory
    host_found_flag = (bool *)malloc(sizeof(bool));
    host_password_found = (password *)malloc(sizeof(password));

    // Allocate device global memory
    cudaMalloc((void **)&device_test_digest, 16 * sizeof(uint8_t));
    cudaMalloc((void **)&device_found_flag, sizeof(bool));
    cudaMalloc((void **)&device_password_found, sizeof(password));
    cudaMalloc((void **)&device_pwd_dict, numPwd * sizeof(password));

    // Copy from host to device memory
    cudaMemcpy(device_test_digest, int_test, 16 * sizeof(uint8_t), cudaMemcpyHostToDevice);
    cudaMemcpy(device_pwd_dict, pwd, numPwd * sizeof(password), cudaMemcpyHostToDevice);

    // Prepare constants in device constant memory

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

    const char* host_charset = "abcdefghijklmnopqrstuvwxyz";

    cudaMemcpyToSymbol(device_k, host_k, 64 * sizeof(uint32_t));
    cudaMemcpyToSymbol(device_r, host_r, 64 * sizeof(uint32_t));
    cudaMemcpyToSymbol(device_h_init, host_h_init, 4 * sizeof(uint32_t));
    cudaMemcpyToSymbol(device_charset, host_charset, 26 * sizeof(char));
    cudaMemcpyToSymbol(device_seq, seq, 20 * sizeof(password));

    startTime(&md5_timer);

    // Reset found flag
    cudaMemset(device_found_flag, false, sizeof(bool));

    // Dictionary attack
    startTime(&dict_timer);
    
    int blocks_needed = ceil(numPwd/(BLOCK_SIZE*PWD_NUM_PER_THREAD));
    int grid_size = 0;
    if (blocks_needed > MAX_GRID_SIZE) {
        grid_size = MAX_GRID_SIZE;
    }
    else {
        grid_size = blocks_needed;
    }
    dim3 block_dim(BLOCK_SIZE, 1, 1);
    dim3 grid_dim(grid_size, 1, 1);

    dict_attack<<<grid_dim, block_dim>>>(device_test_digest, device_pwd_dict, numPwd, device_password_found, device_found_flag);
    cudaDeviceSynchronize();
    cudaMemcpy(host_found_flag, device_found_flag, sizeof(bool), cudaMemcpyDeviceToHost);
    stopTime(&dict_timer);
    printf("Dictionary Time: %f s\n", elapsedTime(dict_timer));

    if (*host_found_flag == true) {
        cudaMemcpy(host_password_found, device_password_found, sizeof(password), cudaMemcpyDeviceToHost);
        printf("The password is: ");
        int pwd_len = (int) host_password_found[0].length;
        for (int j = 0; j < pwd_len; j++) {
            printf("%c", host_password_found[0].word[j]);
        }
        printf("\n\n");
    }
    else {
        printf("The password is not found in dictionary.\n\n");

        printf("Start brute force.\n\n");
        // Brute force
        startTime(&brute_timer);
        int max_num = 1;
        for (int i = 0; i < BRUTE_FORCE_MAX_LEN; i++) {
            max_num *= NUM_CHAR;
            size_t password_length = i + 1;
            printf("Brute force try password length: %d\n", i+1);
            printf("Number of combinations: %d\n\n", max_num);

            // Grid dimensions and block dimensions
            int blocks_needed = ceil(max_num/(BLOCK_SIZE*PWD_NUM_PER_THREAD));
            int grid_size = 0;
            if (blocks_needed > MAX_GRID_SIZE) {
                grid_size = MAX_GRID_SIZE;
            }
            else {
                grid_size = blocks_needed;
            }
            dim3 block_dim(BLOCK_SIZE, 1, 1);
            dim3 grid_dim(grid_size, 1, 1);
            
            // Invoke brute_force
            brute_force<<<grid_dim, block_dim>>>(device_test_digest, password_length, max_num, device_found_flag, device_password_found);
            cudaDeviceSynchronize();

            // Read result
            cudaMemcpy(host_found_flag, device_found_flag, sizeof(bool), cudaMemcpyDeviceToHost);
            if (*host_found_flag == true) {
                cudaMemcpy(host_password_found, device_password_found, sizeof(password), cudaMemcpyDeviceToHost);
                printf("The password is found: ");
                for (int j = 0; j < i + 1; j++) {
                    printf("%c", host_password_found[0].word[j]);
                }
                printf("\n\n");
                break;
            }

            // Scan through all given length
            if (i == BRUTE_FORCE_MAX_LEN-1) {
                printf("The password is not found in brute force.\n\n");
            }
        }
        stopTime(&brute_timer);
        printf("Brute force Time: %f s\n", elapsedTime(brute_timer));
    }

    stopTime(&md5_timer);
    printf("MD5 Time: %f s\n", elapsedTime(md5_timer));

    // Free host and device memory
    cudaFree(device_test_digest);
    cudaFree(device_found_flag);
    cudaFree(device_found_flag);
    free(host_found_flag);
    free(host_password_found);

    stopTime(&gpu_total_timer);
    printf("GPU Time: %f s\n", elapsedTime(gpu_total_timer));

    stopTime(&totaltimer);
    printf("Total Time: %f s\n", elapsedTime(totaltimer));

    if(infile != NULL) fclose (infile);

    return 0;
}