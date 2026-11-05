/*
 * password-cracking
 *
 * We process only the password indices in out assigned
 * half-open range [start, end). Shared project state is declared in
 * hash.c, so it is referenced here with extern declarations.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//"hash_functions.h" was previously included, but is not directly used in this file.
//all necessary declarations are provided via externs or other includes.

#define KEEP 16

//these structures match the definitions in hash.c
struct cracked_hash{
    char hash[2 * KEEP + 1];
    char *password;
    char *alg;
    int match_index;
};

struct thread_arg{
    int start;
    int end;
};

//hash function pointer type and shared globals defined in hash.c
typedef unsigned char *(*hashing)(unsigned char *, unsigned int);

extern char **g_passwords;
extern int g_n_passwords;
extern struct cracked_hash *g_cracked;
extern int g_n_hashed;
extern int n_algs;
extern hashing fn[4];

//functions implemented elsewhere
extern int compare_hashes(char *a, char *b);
extern void try_record_match(int hash_j, int pw_i, int alg_i);

void *crack_worker(void *arg){
    struct thread_arg *range =(struct thread_arg *)arg;
    int start = range->start;
    int end = range->end;

    //process only the passwords assigned
    for(int i = start; i < end; i++){
        unsigned int password_length = (unsigned int)strlen(g_passwords[i]);

        //each thread owns this buffer; it is never shared
        char local_hex[2 * KEEP + 1];
        static const char hex_digits[] = "0123456789abcdef";

        //try each of the four hashing algorithms
        for(int alg_index = 0; alg_index < n_algs; alg_index++){
            unsigned char *hash = fn[alg_index](
                (unsigned char *)g_passwords[i], password_length);

            if(hash == NULL){
                fprintf(stderr, "crack_worker: hash allocation failed\n");
                exit(EXIT_FAILURE);
            }

            //convert the first KEEP digest bytes into hexadecimal
            for(int byte_index = 0; byte_index < KEEP; byte_index++){
                local_hex[2 * byte_index] =
                    hex_digits[(hash[byte_index] >> 4) & 0x0f];
                local_hex[2 * byte_index + 1] =
                    hex_digits[hash[byte_index] & 0x0f];
            }
            local_hex[2 * KEEP] = '\0';

            //the digest is no longer needed after conversion
            free(hash);

            //compare this password/algorithm against every target hash
            for(int j = 0; j < g_n_hashed; j++){
                /*
                 * A password in an earlier range has already won.
                 * Therefore, we cannot produce a lower password index.
                 */
                int existing_match = __atomic_load_n(
                    &g_cracked[j].match_index, __ATOMIC_ACQUIRE);

                if(existing_match != -1 && existing_match < start){
                    continue;
                }

                if(compare_hashes(local_hex, g_cracked[j].hash)){
                    try_record_match(j, i, alg_index);
                }
            }
        }
    }

    return NULL;
}
