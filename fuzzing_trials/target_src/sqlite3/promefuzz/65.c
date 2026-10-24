// This fuzz driver is generated for library sqlite3, aiming to fuzz the following functions:
// sqlite3_mutex_free at sqlite3.c:15891:17 in sqlite3.h
// sqlite3_mutex_leave at sqlite3.c:15928:17 in sqlite3.h
// sqlite3_mutex_enter at sqlite3.c:15902:17 in sqlite3.h
// sqlite3_mutex_alloc at sqlite3.c:15870:27 in sqlite3.h
// sqlite3_mutex_try at sqlite3.c:15913:16 in sqlite3.h
// sqlite3_mutex_held at sqlite3.c:15943:16 in sqlite3.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdlib.h>

static void fuzz_sqlite3_mutex_operations(sqlite3_mutex *mutex) {
    if (!mutex) return;

    // Attempt to enter the mutex
    sqlite3_mutex_enter(mutex);

    // Check if mutex is held
    int held = sqlite3_mutex_held(mutex);

    // Leave the mutex if it is held
    if (held) {
        sqlite3_mutex_leave(mutex);
    }

    // Try acquiring the mutex non-blockingly
    int tryResult = sqlite3_mutex_try(mutex);

    // If try was successful, leave the mutex
    if (tryResult == SQLITE_OK) {
        sqlite3_mutex_leave(mutex);
    }
}

int LLVMFuzzerTestOneInput_65(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return 0;

    // Extract an integer from the input data
    int mutexType = *(int*)Data;

    // Validate mutexType to ensure it is within the valid range
    if (mutexType != SQLITE_MUTEX_FAST && mutexType != SQLITE_MUTEX_RECURSIVE &&
        mutexType != SQLITE_MUTEX_STATIC_MAIN && mutexType != SQLITE_MUTEX_STATIC_MEM &&
        mutexType != SQLITE_MUTEX_STATIC_OPEN && mutexType != SQLITE_MUTEX_STATIC_PRNG &&
        mutexType != SQLITE_MUTEX_STATIC_LRU && mutexType != SQLITE_MUTEX_STATIC_PMEM &&
        mutexType != SQLITE_MUTEX_STATIC_APP1 && mutexType != SQLITE_MUTEX_STATIC_APP2 &&
        mutexType != SQLITE_MUTEX_STATIC_APP3 && mutexType != SQLITE_MUTEX_STATIC_VFS1 &&
        mutexType != SQLITE_MUTEX_STATIC_VFS2 && mutexType != SQLITE_MUTEX_STATIC_VFS3) {
        return 0;
    }

    // Allocate a mutex with the extracted type
    sqlite3_mutex *mutex = sqlite3_mutex_alloc(mutexType);

    // Perform a series of operations on the mutex
    fuzz_sqlite3_mutex_operations(mutex);

    // Free the mutex if it is dynamically allocated
    if (mutexType == SQLITE_MUTEX_FAST || mutexType == SQLITE_MUTEX_RECURSIVE) {
        sqlite3_mutex_free(mutex);
    }

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

        LLVMFuzzerTestOneInput_65(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    