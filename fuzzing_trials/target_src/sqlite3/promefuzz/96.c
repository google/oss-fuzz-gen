// This fuzz driver is generated for library sqlite3, aiming to fuzz the following functions:
// sqlite3_memory_highwater at sqlite3.c:17269:26 in sqlite3.h
// sqlite3_malloc at sqlite3.c:17377:18 in sqlite3.h
// sqlite3_msize at sqlite3.c:17443:27 in sqlite3.h
// sqlite3_free at sqlite3.c:17452:17 in sqlite3.h
// sqlite3_malloc64 at sqlite3.c:17383:18 in sqlite3.h
// sqlite3_free at sqlite3.c:17452:17 in sqlite3.h
// sqlite3_malloc at sqlite3.c:17377:18 in sqlite3.h
// sqlite3_free at sqlite3.c:17452:17 in sqlite3.h
// sqlite3_malloc at sqlite3.c:17377:18 in sqlite3.h
// sqlite3_realloc64 at sqlite3.c:17630:18 in sqlite3.h
// sqlite3_free at sqlite3.c:17452:17 in sqlite3.h
// sqlite3_memory_used at sqlite3.c:17258:26 in sqlite3.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <sqlite3.h>

static void handle_sqlite3_memory_highwater() {
    int resetFlags[] = {0, 1};
    for (int i = 0; i < 2; i++) {
        sqlite3_int64 highwater = sqlite3_memory_highwater(resetFlags[i]);
        // Optionally log or use the highwater value
    }
}

static void handle_sqlite3_msize() {
    void *ptr = sqlite3_malloc(100);
    if (ptr) {
        sqlite3_uint64 size = sqlite3_msize(ptr);
        // Optionally log or use the size value
        sqlite3_free(ptr);
    }
}

static void handle_sqlite3_malloc64() {
    sqlite3_uint64 sizes[] = {0, 50, 1000};
    for (int i = 0; i < 3; i++) {
        void *ptr = sqlite3_malloc64(sizes[i]);
        if (ptr) {
            sqlite3_free(ptr);
        }
    }
}

static void handle_sqlite3_malloc() {
    int sizes[] = {0, 50, 200};
    for (int i = 0; i < 3; i++) {
        void *ptr = sqlite3_malloc(sizes[i]);
        if (ptr) {
            sqlite3_free(ptr);
        }
    }
}

static void handle_sqlite3_realloc64() {
    void *ptr = sqlite3_malloc(100);
    if (ptr) {
        sqlite3_uint64 newSizes[] = {50, 150, 0};
        for (int i = 0; i < 3; i++) {
            void *newPtr = sqlite3_realloc64(ptr, newSizes[i]);
            if (newPtr || newSizes[i] == 0) {
                ptr = newPtr;
            }
        }
        if (ptr) {
            sqlite3_free(ptr);
        }
    }
}

static void handle_sqlite3_memory_used() {
    sqlite3_int64 memoryUsed = sqlite3_memory_used();
    // Optionally log or use the memory used value
}

int LLVMFuzzerTestOneInput_96(const uint8_t *Data, size_t Size) {
    handle_sqlite3_memory_highwater();
    handle_sqlite3_msize();
    handle_sqlite3_malloc64();
    handle_sqlite3_malloc();
    handle_sqlite3_realloc64();
    handle_sqlite3_memory_used();
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

        LLVMFuzzerTestOneInput_96(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    