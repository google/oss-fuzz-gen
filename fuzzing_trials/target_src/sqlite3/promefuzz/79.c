// This fuzz driver is generated for library sqlite3, aiming to fuzz the following functions:
// sqlite3_mutex_notheld at sqlite3.c:15952:16 in sqlite3.h
// sqlite3_mutex_try at sqlite3.c:15913:16 in sqlite3.h
// sqlite3_threadsafe at sqlite3.c:171135:16 in sqlite3.h
// sqlite3_mutex_held at sqlite3.c:15943:16 in sqlite3.h
// sqlite3_mutex_alloc at sqlite3.c:15870:27 in sqlite3.h
// sqlite3_mutex_free at sqlite3.c:15891:17 in sqlite3.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stddef.h>

static void test_sqlite3_mutex_notheld(sqlite3_mutex *mutex) {
    (void)sqlite3_mutex_notheld(mutex);
}

static void test_sqlite3_mutex_try(sqlite3_mutex *mutex) {
    (void)sqlite3_mutex_try(mutex);
}

static void test_sqlite3_threadsafe(void) {
    (void)sqlite3_threadsafe();
}

static void test_sqlite3_mutex_held(sqlite3_mutex *mutex) {
    (void)sqlite3_mutex_held(mutex);
}

int LLVMFuzzerTestOneInput_79(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return 0;

    int mutexType = *((int *)Data);
    sqlite3_mutex *mutex = sqlite3_mutex_alloc(mutexType);

    if (mutex) {
        test_sqlite3_mutex_notheld(mutex);
        test_sqlite3_mutex_try(mutex);
        test_sqlite3_mutex_held(mutex);
        sqlite3_mutex_free(mutex);
    }

    test_sqlite3_threadsafe();

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

        LLVMFuzzerTestOneInput_79(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    