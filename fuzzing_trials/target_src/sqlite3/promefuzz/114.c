// This fuzz driver is generated for library sqlite3, aiming to fuzz the following functions:
// sqlite3_create_collation at sqlite3.c:174754:16 in sqlite3.h
// sqlite3_open at sqlite3.c:174695:16 in sqlite3.h
// sqlite3_create_collation at sqlite3.c:174754:16 in sqlite3.h
// sqlite3_vtab_collation at sqlite3.c:157071:24 in sqlite3.h
// sqlite3_collation_needed at sqlite3.c:174822:16 in sqlite3.h
// sqlite3_table_column_metadata at sqlite3.c:175018:16 in sqlite3.h
// sqlite3_create_module_v2 at sqlite3.c:145711:16 in sqlite3.h
// sqlite3_create_collation_v2 at sqlite3.c:174767:16 in sqlite3.h
// sqlite3_close at sqlite3.c:172361:16 in sqlite3.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sqlite3.h>

// Comparison function for collation
static int customCollation(void* pArg, int len1, const void* str1, int len2, const void* str2) {
    return strncmp((const char*)str1, (const char*)str2, len1 < len2 ? len1 : len2);
}

// Collation needed callback
static void collationNeededCallback(void* pArg, sqlite3* db, int eTextRep, const char* collationName) {
    sqlite3_create_collation(db, collationName, eTextRep, NULL, customCollation);
}

// Fuzz driver entry point
int LLVMFuzzerTestOneInput_114(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    sqlite3 *db;
    sqlite3_open(":memory:", &db);

    char collationName[256];
    snprintf(collationName, sizeof(collationName), "collation_%d", Data[0]);

    // Fuzz sqlite3_create_collation
    sqlite3_create_collation(db, collationName, SQLITE_UTF8, NULL, customCollation);

    // Fuzz sqlite3_vtab_collation
    sqlite3_index_info indexInfo;
    memset(&indexInfo, 0, sizeof(indexInfo));
    indexInfo.nConstraint = 1;
    struct sqlite3_index_constraint constraint;
    memset(&constraint, 0, sizeof(constraint));
    indexInfo.aConstraint = &constraint;
    constraint.iColumn = 0;
    constraint.op = Data[0] % 5;
    constraint.usable = 1;
    constraint.iTermOffset = 0; // Properly initialize iTermOffset
    indexInfo.aOrderBy = NULL;
    indexInfo.aConstraintUsage = (struct sqlite3_index_constraint_usage *)calloc(1, sizeof(struct sqlite3_index_constraint_usage));
    const char* collation = sqlite3_vtab_collation(&indexInfo, 0);
    free(indexInfo.aConstraintUsage);

    // Fuzz sqlite3_collation_needed
    sqlite3_collation_needed(db, NULL, collationNeededCallback);

    // Fuzz sqlite3_table_column_metadata
    const char* dataType;
    const char* collSeq;
    int notNull, primaryKey, autoinc;
    sqlite3_table_column_metadata(db, "main", "sqlite_master", "name", &dataType, &collSeq, &notNull, &primaryKey, &autoinc);

    // Fuzz sqlite3_create_module_v2
    sqlite3_create_module_v2(db, "test_module", NULL, NULL, NULL);

    // Fuzz sqlite3_create_collation_v2
    sqlite3_create_collation_v2(db, collationName, SQLITE_UTF8, NULL, customCollation, NULL);

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

        if(size < 1 + 1)
            exit(0);

        data = (uint8_t *)malloc((size_t)size);
        if(data == NULL)
            exit(0);

        if(fread(data, (size_t)size, 1, f) != 1)
            exit(0);

        LLVMFuzzerTestOneInput_114(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    