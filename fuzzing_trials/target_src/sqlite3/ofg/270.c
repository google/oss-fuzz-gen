#include <stdint.h>
#include <stddef.h>
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_270(const uint8_t *data, size_t size) {
    // Declare and initialize a sqlite3_mutex pointer
    sqlite3_mutex *mutex = sqlite3_mutex_alloc(SQLITE_MUTEX_FAST);

    // Ensure the mutex is not NULL
    if (mutex == NULL) {
        return 0;
    }

    // Enter the mutex to ensure it's in a valid state for leaving
    sqlite3_mutex_enter(mutex);

    // Call the function-under-test
    sqlite3_mutex_leave(mutex);

    // Free the allocated mutex
    sqlite3_mutex_free(mutex);

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

    LLVMFuzzerTestOneInput_270(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
