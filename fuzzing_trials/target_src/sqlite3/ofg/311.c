#include <stdint.h>
#include <stddef.h>  // Include this for size_t
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_311(const uint8_t *data, size_t size) {
    sqlite3_mutex *mutex;

    // Initialize SQLite
    sqlite3_initialize();

    // Create a new mutex
    mutex = sqlite3_mutex_alloc(SQLITE_MUTEX_FAST);
    if (mutex == NULL) {
        return 0; // If mutex allocation fails, return early
    }

    // Call the function-under-test
    int result = sqlite3_mutex_notheld(mutex);

    // Free the mutex
    sqlite3_mutex_free(mutex);

    // Shutdown SQLite
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

    LLVMFuzzerTestOneInput_311(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
