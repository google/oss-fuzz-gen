// This fuzz driver is generated for library sqlite3, aiming to fuzz the following functions:
// sqlite3_shutdown at sqlite3.c:171390:16 in sqlite3.h
// sqlite3_config at sqlite3.c:171444:16 in sqlite3.h
// sqlite3_hard_heap_limit64 at sqlite3.c:17198:26 in sqlite3.h
// sqlite3_hard_heap_limit64 at sqlite3.c:17198:26 in sqlite3.h
// sqlite3_config at sqlite3.c:171444:16 in sqlite3.h
// sqlite3_snprintf at sqlite3.c:19369:18 in sqlite3.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

int LLVMFuzzerTestOneInput_30(const uint8_t *Data, size_t Size) {
    // Step 1: Shutdown the SQLite library
    sqlite3_shutdown();

    // Step 2: Configure SQLite (using a dummy configuration option)
    int config_option = SQLITE_CONFIG_SINGLETHREAD; // Example configuration option
    sqlite3_config(config_option);

    // Step 3: Set a hard heap limit
    sqlite3_int64 heap_limit = Size > sizeof(sqlite3_int64) ? *((sqlite3_int64*)Data) : 0;
    sqlite3_hard_heap_limit64(heap_limit);

    // Step 4: Set another hard heap limit
    heap_limit = Size > 2 * sizeof(sqlite3_int64) ? *((sqlite3_int64*)(Data + sizeof(sqlite3_int64))) : 0;
    sqlite3_hard_heap_limit64(heap_limit);

    // Step 5: Configure SQLite again (using a dummy configuration option)
    sqlite3_config(config_option);

    // Step 6: Use sqlite3_snprintf to format a string
    char buffer[100];
    const char* format = "Formatted data: %d";
    int value = Size > sizeof(int) ? *((int*)Data) : 0;
    sqlite3_snprintf(sizeof(buffer), buffer, format, value);

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

        LLVMFuzzerTestOneInput_30(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    