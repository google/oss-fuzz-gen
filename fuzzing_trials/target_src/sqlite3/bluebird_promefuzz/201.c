#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "sqlite3.h"

int LLVMFuzzerTestOneInput_201(const uint8_t *Data, size_t Size) {
    // Ensure the input data is null-terminated for sqlite3_complete
    char *sql = (char *)malloc(Size + 1);
    if (!sql) return 0;
    memcpy(sql, Data, Size);
    sql[Size] = '\0';

    // Step 1: Test sqlite3_complete
    int complete = sqlite3_complete(sql);

    // Step 2: Since the memory was allocated using malloc, free it using free
    free(sql);

    // Step 3: Test sqlite3_close
    sqlite3 *db;
    sqlite3_open(":memory:", &db);
    int close_result = sqlite3_close(db);

    // Step 4: Test sqlite3_memory_highwater
    sqlite3_int64 highwater = sqlite3_memory_highwater(1);

    // Step 5: Test sqlite3_memory_used
    sqlite3_int64 memory_used_before = sqlite3_memory_used();

    // Step 6: Test sqlite3_status
    int current, highwater_status;
    int status_result = sqlite3_status(SQLITE_STATUS_MEMORY_USED, &current, &highwater_status, 1);

    // Step 7: Test sqlite3_memory_used again
    sqlite3_int64 memory_used_after = sqlite3_memory_used();

    // Step 8: Test sqlite3_hard_heap_limit64
    sqlite3_int64 previous_hard_limit = sqlite3_hard_heap_limit64(1024 * 1024);

    // Step 9: Test sqlite3_soft_heap_limit64
    sqlite3_int64 previous_soft_limit = sqlite3_soft_heap_limit64(512 * 1024);

    // Cleanup: Ensure db is closed
    if (close_result != SQLITE_OK) {
        sqlite3_close(db);
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_201(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
