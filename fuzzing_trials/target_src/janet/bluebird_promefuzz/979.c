#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "janet.h"

static const JanetAbstractType dummy_abstract_type = {
    // Initialize with dummy values or functions as needed
};

int LLVMFuzzerTestOneInput_979(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(size_t)) return 0;

    // Validate abstract_size to prevent excessive allocation
    size_t abstract_size = *(const size_t *)Data;
    if (abstract_size > 1024 * 1024) { // Limit to 1MB for safety
        return 0;
    }
    Data += sizeof(size_t);
    Size -= sizeof(size_t);

    // Ensure Janet VM is initialized before using Janet functions
    janet_init();

    // Test janet_abstract_begin_threaded
    void *abstract = janet_abstract_begin_threaded(&dummy_abstract_type, abstract_size);
    if (abstract == NULL) {
        // Handle out-of-memory error if needed
        janet_deinit();
        return 0;
    }
    // Normally you would initialize the abstract object here

    // Test janet_os_rwlock_rlock
    if (Size >= janet_os_rwlock_size()) {
        JanetOSRWLock *rwlock = (JanetOSRWLock *)malloc(janet_os_rwlock_size());
        if (rwlock) {
            memcpy(rwlock, Data, janet_os_rwlock_size());
            janet_os_rwlock_rlock(rwlock);
            free(rwlock);
            Data += janet_os_rwlock_size();
            Size -= janet_os_rwlock_size();
        }
    }

    // Test janet_os_rwlock_size
    size_t rwlock_size = janet_os_rwlock_size();

    // Test janet_os_mutex_size
    size_t mutex_size = janet_os_mutex_size();

    // Cleanup if necessary
    // Janet's garbage collector will handle abstract cleanup

    // Deinitialize Janet VM
    janet_deinit();

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

    LLVMFuzzerTestOneInput_979(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
