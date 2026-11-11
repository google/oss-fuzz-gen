// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_os_rwlock_rlock at janet.c:1470:6 in janet.h
// janet_os_rwlock_size at janet.c:1438:8 in janet.h
// janet_os_mutex_size at janet.c:1434:8 in janet.h
// janet_os_rwlock_size at janet.c:1438:8 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "janet.h"

static void fuzz_janet_os_rwlock_rlock(const uint8_t *Data, size_t Size) {
    // We cannot determine the size of JanetOSRWLock, so we use janet_os_rwlock_size
    size_t rwlock_size = janet_os_rwlock_size();
    if (Size < rwlock_size) return;

    JanetOSRWLock *rwlock = (JanetOSRWLock *)malloc(rwlock_size);
    if (!rwlock) return;

    memcpy(rwlock, Data, rwlock_size);
    janet_os_rwlock_rlock(rwlock);

    free(rwlock);
}

static void fuzz_janet_os_rwlock_size(void) {
    size_t size = janet_os_rwlock_size();
    (void)size; // Use size for further operations if needed
}

static void fuzz_janet_os_mutex_size(void) {
    size_t size = janet_os_mutex_size();
    (void)size; // Use size for further operations if needed
}

int LLVMFuzzerTestOneInput_93(const uint8_t *Data, size_t Size) {
    fuzz_janet_os_rwlock_rlock(Data, Size);
    fuzz_janet_os_rwlock_size();
    fuzz_janet_os_mutex_size();
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

        if(size < 1 + 1)
            exit(0);

        data = (uint8_t *)malloc((size_t)size);
        if(data == NULL)
            exit(0);

        if(fread(data, (size_t)size, 1, f) != 1)
            exit(0);

        LLVMFuzzerTestOneInput_93(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    