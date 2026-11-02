/* ============================================================================
 * c_sync.c  -  Person C (Password Cracker)
 *
 * Author: Oomat Latipov (U13921223)        <-- fill in your NetID
 *
 * Description:
 *   Person C's half of the threaded cracker. Provides:
 *     - a per-hash mutex array and its init,
 *     - try_record_match(): the "first password in the file wins" tie-break
 *       that stays correct even though worker threads finish out of order,
 *     - current_match_index(): a race-free read of match_index for the skip
 *       optimization in Person B's worker,
 *     - write_output_and_cleanup(): emits results and frees everything.
 *
 *   INTEGRATION (Person A): paste this file into hash.c AFTER the contract
 *   declarations (struct cracked_hash, the g_* globals) and after algs[], and
 *   call init_locks() once, right after load_hashes() and before any
 *   pthread_create(). Everything inside #ifdef C_SYNC_STANDALONE is inert in
 *   hash.c and may be deleted when pasting.
 *
 *   UNIT TEST (no other project files needed):
 *       gcc -Wall -Wextra -DC_SYNC_STANDALONE -pthread c_sync.c -o c_sync_test
 *       ./c_sync_test
 *   Add -fsanitize=thread or -fsanitize=address,undefined to check for data
 *   races and memory errors. run_tests.sh runs all of these for you.
 * ==========================================================================*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

/* ---------------------------------------------------------------------------
 * SHARED CONTRACT (frozen in Phase 0).
 * In hash.c these are already declared by Person A, so the definitions below
 * are compiled ONLY in standalone unit-test builds.
 * Do not change any of these shapes without telling the group.
 * ------------------------------------------------------------------------ */
#ifdef C_SYNC_STANDALONE
#define KEEP 16

struct cracked_hash {
    char  hash[2 * KEEP + 1];
    char *password;
    char *alg;
    int   match_index;            /* file index of matching password; -1 = none */
};

/* globals filled by Person A, read here */
char               **g_passwords;
int                  g_n_passwords;
struct cracked_hash *g_cracked;
int                  g_n_hashed;

/* Test-only table. The real names and order come from the starter's hash.c.
 * alg fields point into this static storage, so they are NEVER freed. */
char *algs[] = { "ALG0", "ALG1", "ALG2", "ALG3" };
#else
extern char               **g_passwords;
extern int                  g_n_passwords;
extern struct cracked_hash *g_cracked;
extern int                  g_n_hashed;
extern char                *algs[];
#endif

/* ---------------------------------------------------------------------------
 * Synchronization state: one mutex per hash entry.
 *
 * Why per-hash rather than one global lock: two threads that find matches for
 * DIFFERENT hashes never block each other. A lock is taken only when a thread
 * actually finds a candidate (rare), so contention is near zero and locking
 * does not limit the speedup.
 * ------------------------------------------------------------------------ */
pthread_mutex_t *g_locks = NULL;

/* Allocate and initialize one mutex per hash entry.
 * Call once, right after load_hashes() has set g_cracked / g_n_hashed and
 * before any worker thread is created. An empty hash file is valid. */
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

/* ---------------------------------------------------------------------------
 * try_record_match - the correctness heart of the project.
 *
 * Called by Person B's crack_worker() every time a worker's computed hash
 * equals g_cracked[hash_j].hash. pw_i is the index of the matching password
 * in the common-passwords file; alg_i indexes algs[].
 *
 * If two passwords hash to the same target, the one EARLIER in the file must
 * win, regardless of which thread got there first. We only accept a match
 * whose password index is lower than what is recorded (-1 = nothing yet).
 * The comparison is strict, so if one password matches under two algorithms,
 * the first algorithm the worker tries stays recorded, as in the baseline.
 * ------------------------------------------------------------------------ */
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

/* ---------------------------------------------------------------------------
 * current_match_index - lock-free read for Person B's skip optimization.
 *
 * Reading g_cracked[j].match_index directly while another thread updates it
 * is a data race (undefined behavior in C). Person B's check should read:
 *
 *     int m = current_match_index(j);
 *     if (m != -1 && m < start) continue;
 *
 * A stale value is harmless: match_index only ever moves to a lower index, so
 * the worst case is one extra compare, followed by a correct locked update.
 * ------------------------------------------------------------------------ */
int current_match_index(int hash_j)
{
    return __atomic_load_n(&g_cracked[hash_j].match_index, __ATOMIC_ACQUIRE);
}

/* ---------------------------------------------------------------------------
 * write_output_and_cleanup - emit results, then release every resource.
 * Call only after every worker has been joined.
 *
 * Writes one line per target hash to `output`, in the original hash order:
 *     password:alg      when cracked
 *     not found         otherwise
 *
 *   >>> OUTPUT MUST MATCH THE BASELINE BYTE FOR BYTE <<<
 *   The format above comes from the group plan. At integration, compare these
 *   two fprintf lines with the print loop in the starter's hash.c. If they
 *   differ, the starter is right.
 * ------------------------------------------------------------------------ */
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

/* ===========================================================================
 * STANDALONE UNIT TEST  (compiled only with -DC_SYNC_STANDALONE)
 * Fakes A's loaders and B's workers. Workers release together and report
 * matches in a different random order each, so a late low index regularly
 * arrives after a high one. Mutation-checked: removing the index comparison
 * or the lock makes this test (or ThreadSanitizer) fail.
 * ========================================================================= */
#ifdef C_SYNC_STANDALONE

#include <unistd.h>

#define T_PASSWORDS 4096
#define T_HASHES    256
#define T_ROUNDS    60
#define T_WORKERS   10            /* + 1 reader + main = 12, the project's cap */

static int  g_failures = 0;
static int  g_go = 0;             /* start line for all test threads */
static int  g_workers_left = 0;
static int  g_all_to_one = 0;     /* 1 = every report targets hash 0 */

static void check(int ok, const char *what)
{
    if (!ok) {
        printf("FAIL %s\n", what);
        g_failures++;
    }
}

static void wait_for_start(void)
{
    while (!__atomic_load_n(&g_go, __ATOMIC_ACQUIRE)) {
        /* spin so that all threads collide as hard as possible */
    }
}

static void setup(int n_passwords, int n_hashes)
{
    g_n_passwords = n_passwords;
    g_passwords = malloc((size_t)(n_passwords > 0 ? n_passwords : 1) * sizeof(char *));
    for (int i = 0; i < n_passwords; i++) {
        char buf[32];
        snprintf(buf, sizeof(buf), "pw%d", i);
        g_passwords[i] = strdup(buf);
    }

    g_n_hashed = n_hashes;
    g_cracked = malloc((size_t)(n_hashes > 0 ? n_hashes : 1) * sizeof(struct cracked_hash));
    for (int j = 0; j < n_hashes; j++) {
        snprintf(g_cracked[j].hash, sizeof(g_cracked[j].hash), "HASH%d", j);
        g_cracked[j].password    = NULL;
        g_cracked[j].alg         = NULL;
        g_cracked[j].match_index = -1;
    }
    init_locks();
}

/* Reports every password index once, in a per-thread random order. */
static void *fake_worker(void *arg)
{
    unsigned int state = *(unsigned int *)arg;
    int order[T_PASSWORDS];

    for (int i = 0; i < T_PASSWORDS; i++) {
        order[i] = i;
    }
    for (int i = T_PASSWORDS - 1; i > 0; i--) {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        int k = (int)(state % (unsigned int)(i + 1));
        int tmp = order[i];
        order[i] = order[k];
        order[k] = tmp;
    }

    wait_for_start();
    for (int n = 0; n < T_PASSWORDS; n++) {
        int i = order[n];
        try_record_match(g_all_to_one ? 0 : i % T_HASHES, i, i % 4);
    }
    __atomic_fetch_sub(&g_workers_left, 1, __ATOMIC_ACQ_REL);
    return NULL;
}

/* Plays Person B's unlocked skip check: a hash's index may only ever fall. */
static void *fake_reader(void *arg)
{
    int *regressions = arg;
    int last[T_HASHES];

    for (int j = 0; j < T_HASHES; j++) {
        last[j] = -1;
    }
    wait_for_start();
    while (__atomic_load_n(&g_workers_left, __ATOMIC_ACQUIRE) > 0) {
        for (int j = 0; j < T_HASHES; j++) {
            int m = current_match_index(j);
            if (last[j] != -1 && (m == -1 || m > last[j])) {
                (*regressions)++;
            }
            last[j] = m;
        }
    }
    return NULL;
}

static void test_race_round(int round)
{
    pthread_t workers[T_WORKERS], reader;
    unsigned int seeds[T_WORKERS];
    int regressions = 0;
    int n_hashes = T_HASHES;

    g_all_to_one = round % 2;
    setup(T_PASSWORDS, n_hashes);
    g_go = 0;
    g_workers_left = T_WORKERS;

    for (int t = 0; t < T_WORKERS; t++) {
        seeds[t] = 2463534242u + (unsigned int)(round * 131 + t * 7919);
        if (pthread_create(&workers[t], NULL, fake_worker, &seeds[t]) != 0) {
            printf("FAIL pthread_create\n");
            exit(EXIT_FAILURE);
        }
    }
    if (pthread_create(&reader, NULL, fake_reader, &regressions) != 0) {
        printf("FAIL pthread_create\n");
        exit(EXIT_FAILURE);
    }
    __atomic_store_n(&g_go, 1, __ATOMIC_RELEASE);
    for (int t = 0; t < T_WORKERS; t++) {
        pthread_join(workers[t], NULL);
    }
    pthread_join(reader, NULL);

    check(regressions == 0, "match_index moved up or was lost during the race");
    for (int j = 0; j < n_hashes; j++) {
        /* hash j's lowest reporter is j; with all reports on hash 0, only 0
         * ever matches and the others stay "not found". */
        int want = g_all_to_one ? (j == 0 ? 0 : -1) : j;
        char pw[32];

        check(g_cracked[j].match_index == want, "wrong tie-break winner");
        if (want >= 0) {
            snprintf(pw, sizeof(pw), "pw%d", want);
            check(g_cracked[j].password != NULL &&
                  strcmp(g_cracked[j].password, pw) == 0,
                  "password does not belong to the winning index");
            check(g_cracked[j].alg == algs[want % 4],
                  "alg does not belong to the winning index");
        }
    }
    write_output_and_cleanup("/dev/null");
}

/* Fixed-order cases: each outcome is certain, so a failure is never luck. */
static void test_tie_break_rules(void)
{
    setup(8, 1);
    try_record_match(0, 5, 1);
    check(g_cracked[0].match_index == 5, "first match not recorded");
    try_record_match(0, 7, 2);
    check(g_cracked[0].match_index == 5, "later password replaced an earlier one");
    try_record_match(0, 2, 3);
    check(g_cracked[0].match_index == 2, "earlier password did not replace a later one");
    check(strcmp(g_cracked[0].password, "pw2") == 0, "password not replaced");
    check(g_cracked[0].alg == algs[3], "alg not replaced");
    try_record_match(0, 2, 0);
    check(g_cracked[0].alg == algs[3], "same password's later alg replaced the first");
    try_record_match(0, 0, 0);
    check(current_match_index(0) == 0, "index 0 must be able to win (not 'unset')");
    write_output_and_cleanup("/dev/null");
}

/* Writes via the real function and compares the file byte for byte. */
static void check_output_file(const char *want, const char *what)
{
    char path[] = "/tmp/c_sync_test_XXXXXX";
    char got[256] = { 0 };
    int fd = mkstemp(path);

    if (fd < 0) {
        printf("FAIL mkstemp\n");
        exit(EXIT_FAILURE);
    }
    close(fd);

    write_output_and_cleanup(path);

    FILE *f = fopen(path, "r");
    size_t n = f ? fread(got, 1, sizeof(got) - 1, f) : 0;
    if (f) {
        fclose(f);
    }
    unlink(path);
    got[n] = '\0';
    check(strcmp(got, want) == 0, what);
}

static void test_output_format(void)
{
    /* hash order, not match order; misses printed in place */
    setup(4, 3);
    try_record_match(2, 3, 1);
    try_record_match(0, 1, 0);
    check_output_file("pw1:ALG0\nnot found\npw3:ALG1\n", "output format/order is wrong");
    check(g_locks == NULL && g_cracked == NULL && g_passwords == NULL,
          "cleanup left a dangling global");

    setup(4, 0);                  /* empty hash file */
    check_output_file("", "empty hash list must give an empty file");

    setup(0, 2);                  /* empty password file */
    check_output_file("not found\nnot found\n", "empty password list must miss all");

    /* a second load in the same process must work after cleanup */
    setup(1, 1);
    try_record_match(0, 0, 2);
    check_output_file("pw0:ALG2\n", "state leaked from the previous run");
}

int main(void)
{
    test_tie_break_rules();
    printf("ok   tie-break rules\n");

    test_output_format();
    printf("ok   output format, empty inputs, repeat run\n");

    for (int round = 0; round < T_ROUNDS; round++) {
        test_race_round(round);
    }
    printf("ok   %d race rounds (%d workers + 1 reader, %d passwords, %d hashes)\n",
           T_ROUNDS, T_WORKERS, T_PASSWORDS, T_HASHES);

    if (g_failures == 0) {
        printf("\nALL TIE-BREAK TESTS PASSED\n");
        return 0;
    }
    printf("\n%d FAILURE(S)\n", g_failures);
    return 1;
}

#endif /* C_SYNC_STANDALONE */
