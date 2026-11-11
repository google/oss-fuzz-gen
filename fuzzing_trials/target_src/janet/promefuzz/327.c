// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_os_rwlock_init at janet.c:1462:6 in janet.h
// janet_os_rwlock_rlock at janet.c:1470:6 in janet.h
// janet_os_rwlock_runlock at janet.c:1478:6 in janet.h
// janet_os_rwlock_wlock at janet.c:1474:6 in janet.h
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
#include "janet.h"

struct JanetOSRWLock {
    // Assuming the actual definition is hidden, use a placeholder
    char placeholder[64];
};

static void fuzz_rwlock_operations(JanetOSRWLock *rwlock, const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    // Initialize the lock
    janet_os_rwlock_init(rwlock);

    for (size_t i = 0; i < Size; i++) {
        switch (Data[i] % 6) {
            case 0:
                janet_os_rwlock_rlock(rwlock);
                break;
            case 1:
                janet_os_rwlock_runlock(rwlock);
                break;
            case 2:
                janet_os_rwlock_wlock(rwlock);
                break;
            case 3:
                janet_os_rwlock_wunlock(rwlock);
                break;
            case 4:
                janet_os_rwlock_deinit(rwlock);
                break;
            case 5:
                janet_os_rwlock_init(rwlock);
                break;
        }
    }

    // Ensure the lock is deinitialized at the end
    janet_os_rwlock_deinit(rwlock);
}

int LLVMFuzzerTestOneInput_327(const uint8_t *Data, size_t Size) {
    JanetOSRWLock rwlock;
    fuzz_rwlock_operations(&rwlock, Data, Size);
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

        LLVMFuzzerTestOneInput_327(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    