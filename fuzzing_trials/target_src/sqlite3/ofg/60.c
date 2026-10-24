#include <stdint.h>
#include <stddef.h>
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_60(const uint8_t *data, size_t size) {
    sqlite3_mutex *mutex;

    // Initialize the SQLite library
    if (sqlite3_initialize() != SQLITE_OK) {
        return 0;
    }

    // Create a mutex for testing
    mutex = sqlite3_mutex_alloc(SQLITE_MUTEX_FAST);
    if (mutex == NULL) {
        sqlite3_shutdown();
        return 0;
    }

    // Lock the mutex to ensure it's held
    sqlite3_mutex_enter(mutex);

    // Call the function-under-test with more realistic input
    // Use the input data to introduce variability
    if (size > 0) {
        int result = 0;
        if (data[0] % 2 == 0) {
            result = sqlite3_mutex_held(mutex);
        } else {
            // Introduce a scenario where we unlock the mutex and check if it's held
            sqlite3_mutex_leave(mutex);
            result = sqlite3_mutex_held(mutex);
            // Re-lock the mutex for cleanup
            sqlite3_mutex_enter(mutex);
        }

        // Use the result in some way to prevent compiler optimizations from removing it
        if (result) {
            // Do something with the result to simulate usage
            volatile int use_result = result;
        }
    }

    // Unlock and free the mutex
    sqlite3_mutex_leave(mutex);
    sqlite3_mutex_free(mutex);

    // Shutdown the SQLite library
    sqlite3_shutdown();

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

    LLVMFuzzerTestOneInput_60(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
