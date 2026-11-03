//Project 2 - Multithreaded Password Cracker
//Group 15
//Destiny Gonzalez

//Description:

/*

All candidate passwords are loaded into memory and split into
contiguous ranges that are processed by NUM_THREADS worker threads.
Each worker hashes its passwords with the four algorithms
and the record matches. Whenever several passwords match with the same
hash, the first one to appear in the password file is reported. 
This is preserved by storing each match's password index and only 
keeping the lowest one.

*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>
#include "hash_functions.h"

//Shared declarations agreed by entire group
//DONT CHANGE

#define KEEP 16 		//first 16 bytes of a hash are kept
#define NUM_THREADS 4   //Worker threads (+ main = 5, under the 12 cap)

struct cracked_hash {
	char hash[2*KEEP+1];
	char *password, *alg;
	int match_index;		//File inex of the match password -> -1 indicates no match yet
};


//One password range is handed to a worker: [start, end)
struct thread_arg {int start; int end;};

//Shared state: filled by Person A, read by the workers Person B
//Written through try_record_match Person C
char **g_passwords;		//All candidate passwords in the file order
int g_n_passwords; 		//Number of candidate passwords
struct cracked_hash *g_cracked; //Target hashes + their results
int g_n_hashed;				//Number of target hashes
pthread_mutex_t *g_locks;	//One mutex per hash entry (PersonC)

//Function prototypes 
void load_hashes(const char *path);			//A
void load_passwords(const char *path);		//A
void init_locks(void);						//C
void *crack_worker(void *arg);				//B
void try_record_match(int hash_j, int pw_i, int alg_i);	//C
void write_output_and_cleanup(const char *output);		//C
int current_match_index(int hash_j);		//C


//Algorithm tables + hash comparison (used by Person B)

typedef unsigned char * (*hashing)(unsigned char *, unsigned int);

int n_algs = 4;
hashing fn[4] = {calculate_md5, calculate_sha1, calculate_sha256, calculate_sha512};
char *algs[4] = {"MD5", "SHA1", "SHA256", "SHA512"};

int compare_hashes(char *a, char *b) {
	for(int i=0; i < 2*KEEP; i++)
	if(a[i] != b[i])
		return 0;
	return 1;
}

//Scafolding, loading, threading

//Loads target hashes from file into c_cracked and counts
//the lines first, then allocates the array, and reads each
//hash, clearing its result fields.

void load_hashes(const char *path){
	FILE *fp = fopen(path, "r");
	assert(fp != NULL);

	char buf[2*KEEP + 1];
	g_n_hashed = 0;
	while(fscanf(fp, "%s", buf) ==1)
		g_n_hashed++;
	rewind(fp);

	g_cracked = (struct cracked_hash *) malloc(g_n_hashed * sizeof(struct cracked_hash));
	assert(g_cracked != NULL);

	for(int i=0; i < g_n_hashed; i++){
		fscanf(fp, "%s", g_cracked[i].hash);
		g_cracked[i].password = NULL;
		g_cracked[i].alg = NULL;
		g_cracked[i].match_index = -1;
	}
	fclose(fp);
}

//Loads all candidate passwords from the file into c_passwords,
//preserving the order. Also counts lines first, then allocates
//the pointer array and finally, copies each password

void load_passwords(const char *path){
	FILE *fp = fopen(path, "r");
	assert(fp != NULL);

	char buf[256];
	g_n_passwords = 0;
	while(fscanf(fp, "%s", buf) == 1)
		g_n_passwords++;
	rewind(fp);

	g_passwords = (char **) malloc(g_n_passwords * sizeof(char *));
	assert(g_passwords != NULL);

	for(int i = 0; i < g_n_passwords; i++) {
		fscanf(fp, "%s", buf);
		g_passwords[i] = strdup(buf);
		assert(g_passwords[i] != NULL);
	}
	fclose(fp);
}

//Loads all the inputs and splits the password list into NUM_THREADS
//contiguous ranges, running one worker thread per range,
//waiting for all of them and writing the results.

void crack_hashed_passwords(char *password_list, char *hashed_list, char *output){
	load_hashes(hashed_list);
	load_passwords(password_list);
	init_locks();

	pthread_t threads[NUM_THREADS];
	struct thread_arg args[NUM_THREADS];

	//Splits [0, c_n_passwords] into NUM_THREADS near equal contiguous ranges,
	//while avoiding any overflow when the password list is large.
	for(int t=0; t < NUM_THREADS; t++){
		args[t].start = (int)((long) t * g_n_passwords / NUM_THREADS);
		args[t].end = (int)((long)(t+1) * g_n_passwords / NUM_THREADS);
		pthread_create(&threads[t], NULL, crack_worker, &args[t]);
	}

	for(int t=0; t < NUM_THREADS; t++)
		pthread_join(threads[t], NULL);
	
	write_output_and_cleanup(output); //Person C
}

//Placeholders - replaced by Person B and C

//Person C implements
void init_locks(void)
{
    g_locks = NULL;
    if (g_n_hashed <= 0) {
        return;                   /* malloc(0) may return NULL; nothing to lock */
    }

    g_locks = malloc((size_t)g_n_hashed * sizeof(pthread_mutex_t));
    if (g_locks == NULL) {
        fprintf(stderr, "init_locks: out of memory\n");
        exit(EXIT_FAILURE);
    }
    for (int j = 0; j < g_n_hashed; j++) {
        if (pthread_mutex_init(&g_locks[j], NULL) != 0) {
            fprintf(stderr, "init_locks: pthread_mutex_init failed\n");
            exit(EXIT_FAILURE);
        }
    }
}


//Person C implements (real version does index-based tie break)
void try_record_match(int hash_j, int pw_i, int alg_i)
{
    pthread_mutex_lock(&g_locks[hash_j]);

    if (g_cracked[hash_j].match_index == -1 ||
        pw_i < g_cracked[hash_j].match_index) {

        /* Copy first: on failure the old winner must not be left dangling. */
        char *copy = strdup(g_passwords[pw_i]);
        if (copy == NULL) {
            fprintf(stderr, "try_record_match: out of memory\n");
            exit(EXIT_FAILURE);
        }

        /* a previous (later-in-file) winner may be sitting here; replace it */
        free(g_cracked[hash_j].password);          /* free(NULL) is safe */
        g_cracked[hash_j].password = copy;
        g_cracked[hash_j].alg      = algs[alg_i];  /* points into static table */

        /* Atomic because current_match_index() reads it without the lock. */
        __atomic_store_n(&g_cracked[hash_j].match_index, pw_i, __ATOMIC_RELEASE);
    }

    pthread_mutex_unlock(&g_locks[hash_j]);
}

//Person B implements current_match_index
int current_match_index(int hash_j)
{
    return __atomic_load_n(&g_cracked[hash_j].match_index, __ATOMIC_ACQUIRE);
}

//Person B implements (real version hashes each password & compares)
void *crack_worker(void *arg){
	(void)arg; //no-op placeholder: does no cracking as of yet
	return NULL;
}

//Person C implements (real version writes results & frees memory)
void write_output_and_cleanup(const char *output)
{
    FILE *out = fopen(output, "w");
    if (out == NULL) {
        perror("write_output_and_cleanup: fopen");
        exit(EXIT_FAILURE);
    }

    for (int j = 0; j < g_n_hashed; j++) {
        if (g_cracked[j].match_index != -1) {
            fprintf(out, "%s:%s\n", g_cracked[j].password, g_cracked[j].alg);
        } else {
            fprintf(out, "not found\n");
        }
    }

    /* A full disk must fail loudly, not leave a silently truncated answer. */
    if (ferror(out) || fclose(out) != 0) {
        perror("write_output_and_cleanup: write");
        exit(EXIT_FAILURE);
    }

    /* ---- teardown (per-entry locks + passwords, then the arrays) ---- */
    for (int j = 0; j < g_n_hashed; j++) {
        if (g_locks != NULL) {
            pthread_mutex_destroy(&g_locks[j]);
        }
        free(g_cracked[j].password);      /* alg is NOT freed: static storage */
    }
    free(g_locks);
    g_locks = NULL;
    free(g_cracked);
    g_cracked = NULL;
    g_n_hashed = 0;

    for (int i = 0; i < g_n_passwords; i++) {
        free(g_passwords[i]);
    }
    free(g_passwords);
    g_passwords = NULL;
    g_n_passwords = 0;
}