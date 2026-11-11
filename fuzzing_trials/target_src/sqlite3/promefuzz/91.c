// This fuzz driver is generated for library sqlite3, aiming to fuzz the following functions:
// sqlite3_open at sqlite3.c:174695:16 in sqlite3.h
// sqlite3_errcode at sqlite3.c:173827:16 in sqlite3.h
// sqlite3_create_collation at sqlite3.c:174754:16 in sqlite3.h
// sqlite3_log at sqlite3.c:19424:17 in sqlite3.h
// sqlite3_errstr at sqlite3.c:173854:24 in sqlite3.h
// sqlite3_set_errmsg at sqlite3.c:173751:16 in sqlite3.h
// sqlite3_errmsg at sqlite3.c:173721:24 in sqlite3.h
// sqlite3_close at sqlite3.c:172361:16 in sqlite3.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

static void customLogFunction(void *pArg, int iErrCode, const char *zMsg) {
    // Custom logging function for sqlite3_log
    (void)pArg;
    (void)iErrCode;
    (void)zMsg;
}

static int customCollation(void *pArg, int len1, const void *str1, int len2, const void *str2) {
    // Custom collation function for sqlite3_create_collation
    (void)pArg;
    (void)len1;
    (void)str1;
    (void)len2;
    (void)str2;
    return 0;
}

int LLVMFuzzerTestOneInput_91(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    sqlite3 *db;
    int rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Fuzzing sqlite3_errcode
    int errCode = sqlite3_errcode(db);

    // Fuzzing sqlite3_create_collation
    sqlite3_create_collation(db, "custom_collation", SQLITE_UTF8, NULL, customCollation);

    // Fuzzing sqlite3_log
    sqlite3_log(SQLITE_ERROR, "Test log message with code %d", errCode);

    // Fuzzing sqlite3_errstr
    const char *errStr = sqlite3_errstr(errCode);

    // Fuzzing sqlite3_set_errmsg
    sqlite3_set_errmsg(db, SQLITE_ERROR, "Custom error message");

    // Fuzzing sqlite3_errmsg
    const char *errMsg = sqlite3_errmsg(db);

    // Cleanup
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

        LLVMFuzzerTestOneInput_91(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    