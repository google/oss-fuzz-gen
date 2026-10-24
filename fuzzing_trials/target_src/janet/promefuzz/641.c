// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_os_mutex_init at janet.c:1442:6 in janet.h
// janet_os_mutex_lock at janet.c:1453:6 in janet.h
// janet_os_mutex_unlock at janet.c:1457:6 in janet.h
// janet_os_mutex_deinit at janet.c:1449:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <pthread.h>
#include "janet.h"

typedef struct JanetOSMutex {
    pthread_mutex_t mutex;
} JanetOSMutex;

static void initialize_mutex(JanetOSMutex *mutex) {
    janet_os_mutex_init(mutex);
}

static void lock_mutex(JanetOSMutex *mutex) {
    janet_os_mutex_lock(mutex);
}

static void unlock_mutex(JanetOSMutex *mutex) {
    janet_os_mutex_unlock(mutex);
}

static void deinitialize_mutex(JanetOSMutex *mutex) {
    janet_os_mutex_deinit(mutex);
}

int LLVMFuzzerTestOneInput_641(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(JanetOSMutex)) {
        return 0;
    }

    JanetOSMutex mutex;
    initialize_mutex(&mutex);

    // Simulate different states of the mutex
    if (Size % 2 == 0) {
        lock_mutex(&mutex);
        // Attempt to unlock and lock again, testing recursive behavior
        unlock_mutex(&mutex);
        lock_mutex(&mutex);
    } else {
        // Test deinitializing without lock
        deinitialize_mutex(&mutex);
        return 0;
    }

    // Unlock and deinitialize the mutex
    unlock_mutex(&mutex);
    deinitialize_mutex(&mutex);

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

        LLVMFuzzerTestOneInput_641(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    