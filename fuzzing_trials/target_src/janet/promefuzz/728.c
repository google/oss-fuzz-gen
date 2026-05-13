// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_os_mutex_init at janet.c:1442:6 in janet.h
// janet_os_mutex_lock at janet.c:1453:6 in janet.h
// janet_os_mutex_unlock at janet.c:1457:6 in janet.h
// janet_os_mutex_deinit at janet.c:1449:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_728(const uint8_t *Data, size_t Size) {
    // Allocate memory for JanetOSMutex using a reasonable size
    JanetOSMutex *mutex = (JanetOSMutex *)malloc(128); // Assume 128 bytes is sufficient for the mutex
    if (!mutex) {
        return 0; // Memory allocation failed, return early
    }

    // Initialize the mutex
    janet_os_mutex_init(mutex);

    // Lock the mutex
    janet_os_mutex_lock(mutex);

    // Unlock the mutex
    janet_os_mutex_unlock(mutex);

    // Deinitialize the mutex
    janet_os_mutex_deinit(mutex);

    // Free the allocated memory
    free(mutex);

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

        LLVMFuzzerTestOneInput_728(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    