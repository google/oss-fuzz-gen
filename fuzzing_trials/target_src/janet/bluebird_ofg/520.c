#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "janet.h" // Assuming this is the header where JanetOSRWLock is defined

// Define the JanetOSRWLock structure if not defined
typedef struct JanetOSRWLock {
    int readers;
    int writer;
    void *lock;
} JanetOSRWLock;

int LLVMFuzzerTestOneInput_520(const uint8_t *data, size_t size) {
    JanetOSRWLock lock;

    // Initialize the lock with some non-NULL values
    lock.readers = 0;
    lock.writer = 0;
    lock.lock = (void *)data; // Using data as a dummy pointer to avoid NULL

    // Call the function-under-test
    janet_os_rwlock_deinit(&lock);

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

    LLVMFuzzerTestOneInput_520(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
