#include <stdint.h>
#include <stddef.h>
#include <string.h> // Include for memcpy
#include "/src/janet/src/include/janet.h" // Correct path for janet.h

extern void janet_os_rwlock_runlock(JanetOSRWLock *);

// Assuming a reasonable size for JanetOSRWLock for fuzzing purposes
#define JANET_OS_RWLOCK_SIZE 64

int LLVMFuzzerTestOneInput_391(const uint8_t *data, size_t size) {
    if (size < JANET_OS_RWLOCK_SIZE) {
        return 0;
    }

    // Allocate memory for rwlock and initialize it with some data from the fuzz input
    JanetOSRWLock *rwlock = (JanetOSRWLock *)malloc(JANET_OS_RWLOCK_SIZE);
    if (rwlock == NULL) {
        return 0; // Handle allocation failure
    }

    memcpy(rwlock, data, JANET_OS_RWLOCK_SIZE);

    // Call the function-under-test
    janet_os_rwlock_runlock(rwlock);

    // Free the allocated memory
    free(rwlock);

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

    LLVMFuzzerTestOneInput_391(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
