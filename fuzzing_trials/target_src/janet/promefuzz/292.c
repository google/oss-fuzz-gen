// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_os_rwlock_init at janet.c:1462:6 in janet.h
// janet_os_rwlock_wlock at janet.c:1474:6 in janet.h
// janet_os_rwlock_wunlock at janet.c:1482:6 in janet.h
// janet_os_rwlock_rlock at janet.c:1470:6 in janet.h
// janet_os_rwlock_runlock at janet.c:1478:6 in janet.h
// janet_os_rwlock_wlock at janet.c:1474:6 in janet.h
// janet_os_rwlock_wunlock at janet.c:1482:6 in janet.h
// janet_os_rwlock_rlock at janet.c:1470:6 in janet.h
// janet_os_rwlock_runlock at janet.c:1478:6 in janet.h
// janet_os_rwlock_rlock at janet.c:1470:6 in janet.h
// janet_os_rwlock_rlock at janet.c:1470:6 in janet.h
// janet_os_rwlock_runlock at janet.c:1478:6 in janet.h
// janet_os_rwlock_runlock at janet.c:1478:6 in janet.h
// janet_os_rwlock_wlock at janet.c:1474:6 in janet.h
// janet_os_rwlock_rlock at janet.c:1470:6 in janet.h
// janet_os_rwlock_runlock at janet.c:1478:6 in janet.h
// janet_os_rwlock_wunlock at janet.c:1482:6 in janet.h
// janet_os_rwlock_deinit at janet.c:1466:6 in janet.h
// janet_os_rwlock_init at janet.c:1462:6 in janet.h
// janet_os_rwlock_deinit at janet.c:1466:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "janet.h"

// Define the JanetOSRWLock structure as it is not defined in the header
struct JanetOSRWLock {
    // Assuming a pthread_rwlock_t for demonstration purposes
    pthread_rwlock_t rwlock;
};

int LLVMFuzzerTestOneInput_292(const uint8_t *Data, size_t Size) {
    // Initialize a JanetOSRWLock
    JanetOSRWLock rwlock;
    janet_os_rwlock_init(&rwlock);

    if (Size > 0) {
        // Use the data to decide which function to call
        switch (Data[0] % 6) {
            case 0:
                // Acquire a write lock
                janet_os_rwlock_wlock(&rwlock);
                // Release the write lock
                janet_os_rwlock_wunlock(&rwlock);
                break;
            case 1:
                // Acquire a read lock
                janet_os_rwlock_rlock(&rwlock);
                // Release the read lock
                janet_os_rwlock_runlock(&rwlock);
                break;
            case 2:
                // Acquire a write lock and release it
                janet_os_rwlock_wlock(&rwlock);
                janet_os_rwlock_wunlock(&rwlock);
                // Acquire a read lock and release it
                janet_os_rwlock_rlock(&rwlock);
                janet_os_rwlock_runlock(&rwlock);
                break;
            case 3:
                // Acquire multiple read locks
                janet_os_rwlock_rlock(&rwlock);
                janet_os_rwlock_rlock(&rwlock);
                // Release the read locks
                janet_os_rwlock_runlock(&rwlock);
                janet_os_rwlock_runlock(&rwlock);
                break;
            case 4:
                // Acquire write lock, then read lock (should block)
                janet_os_rwlock_wlock(&rwlock);
                janet_os_rwlock_rlock(&rwlock); // This may block indefinitely
                janet_os_rwlock_runlock(&rwlock);
                janet_os_rwlock_wunlock(&rwlock);
                break;
            case 5:
                // Randomly deinitialize and reinitialize
                janet_os_rwlock_deinit(&rwlock);
                janet_os_rwlock_init(&rwlock);
                break;
        }
    }

    // Deinitialize the lock
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

        if(size < 1 + 1)
            exit(0);

        data = (uint8_t *)malloc((size_t)size);
        if(data == NULL)
            exit(0);

        if(fread(data, (size_t)size, 1, f) != 1)
            exit(0);

        LLVMFuzzerTestOneInput_292(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    