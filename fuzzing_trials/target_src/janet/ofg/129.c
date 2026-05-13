#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>

// Define the JanetOSRWLock structure
typedef struct {
    pthread_rwlock_t lock;
} JanetOSRWLock;

// Function-under-test
void janet_os_rwlock_deinit(JanetOSRWLock *rwlock);

// Fuzzing harness
int LLVMFuzzerTestOneInput_129(const uint8_t *data, size_t size) {
    // Ensure we have enough data to initialize the lock
    if (size < sizeof(JanetOSRWLock)) {
        return 0;
    }

    // Allocate and initialize the JanetOSRWLock
    JanetOSRWLock rwlock;
    pthread_rwlock_init(&rwlock.lock, NULL);

    // Call the function-under-test
    janet_os_rwlock_deinit(&rwlock);

    return 0;
}
#ifdef INC_MAIN
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
int main(int argc, char *argv[])
{
    FILE *f;
    uint8_t *data = NULL;
    long size;

    if(argc < 2)
        exit(0);

    f = fopen(argv[1], "rb");
    if(f == NULL)
        exit(0);

    fseek(f, 0, SEEK_END);

    size = ftell(f);
    rewind(f);

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_129(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
