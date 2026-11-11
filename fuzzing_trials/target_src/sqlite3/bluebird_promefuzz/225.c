#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "sqlite3.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Dummy comparison function for collation
static int xCompare(void* pArg, int len1, const void* str1, int len2, const void* str2) {
    return memcmp(str1, str2, len1 < len2 ? len1 : len2);
}

// Dummy function callbacks for user-defined functions
static void xFunc(sqlite3_context* context, int argc, sqlite3_value** argv) {}
static void xStep(sqlite3_context* context, int argc, sqlite3_value** argv) {}
static void xFinal(sqlite3_context* context) {}
static void xDestroy(void* p) {}

// Dummy collation needed callback
static void collationNeededCallback(void* pArg, sqlite3* db, int eTextRep, const void* name) {}

int LLVMFuzzerTestOneInput_225(const uint8_t *Data, size_t Size) {
    if (Size < 2) return 0; // Ensure there's enough data for UTF-16 string

    // Initialize SQLite
    sqlite3 *db;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
        return 0;
    }

    // Prepare a UTF-16 null-terminated string from the input
    size_t utf16_size = Size / 2;
    uint16_t *utf16_str = (uint16_t *)sqlite3_malloc((utf16_size + 1) * sizeof(uint16_t));
    if (!utf16_str) {
        sqlite3_close(db);
        return 0;
    }
    memcpy(utf16_str, Data, utf16_size * sizeof(uint16_t));
    utf16_str[utf16_size] = 0; // Null-terminate

    // Ensure null-termination for ASCII strings
    char *ascii_str = (char *)sqlite3_malloc(Size + 1);
    if (!ascii_str) {
        sqlite3_free(utf16_str);
        sqlite3_close(db);
        return 0;
    }
    memcpy(ascii_str, Data, Size);
    ascii_str[Size] = '\0';

    // Fuzz sqlite3_create_collation16
    sqlite3_create_collation16(db, utf16_str, SQLITE_UTF16, NULL, xCompare);

    // Fuzz sqlite3_collation_needed16
    sqlite3_collation_needed16(db, NULL, collationNeededCallback);

    // Fuzz sqlite3_create_function16
    sqlite3_create_function16(db, utf16_str, 1, SQLITE_UTF16, NULL, xFunc, xStep, xFinal);

    // Fuzz sqlite3_overload_function
    sqlite3_overload_function(db, ascii_str, 1);

    // Fuzz sqlite3_create_function_v2
    sqlite3_create_function_v2(db, ascii_str, 1, SQLITE_UTF8, NULL, xFunc, xStep, xFinal, xDestroy);

    // Fuzz sqlite3_create_function
    sqlite3_create_function(db, ascii_str, 1, SQLITE_UTF8, NULL, xFunc, xStep, xFinal);

    // Cleanup
    sqlite3_free(utf16_str);
    sqlite3_free(ascii_str);
    sqlite3_close(db);

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

    LLVMFuzzerTestOneInput_225(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
