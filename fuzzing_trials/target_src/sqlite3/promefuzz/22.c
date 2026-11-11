// This fuzz driver is generated for library sqlite3, aiming to fuzz the following functions:
// sqlite3_open at sqlite3.c:174695:16 in sqlite3.h
// sqlite3_prepare_v2 at sqlite3.c:132572:16 in sqlite3.h
// sqlite3_close at sqlite3.c:172361:16 in sqlite3.h
// sqlite3_step at sqlite3.c:79246:16 in sqlite3.h
// sqlite3_column_text at sqlite3.c:79749:33 in sqlite3.h
// sqlite3_mprintf at sqlite3.c:19329:18 in sqlite3.h
// sqlite3_str_new at sqlite3.c:19257:25 in sqlite3.h
// sqlite3_str_appendf at sqlite3.c:19465:17 in sqlite3.h
// sqlite3_str_appendf at sqlite3.c:19465:17 in sqlite3.h
// sqlite3_free at sqlite3.c:17452:17 in sqlite3.h
// sqlite3_str_finish at sqlite3.c:19172:18 in sqlite3.h
// sqlite3_free at sqlite3.c:17452:17 in sqlite3.h
// sqlite3_finalize at sqlite3.c:78432:16 in sqlite3.h
// sqlite3_close at sqlite3.c:172361:16 in sqlite3.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void writeDummyFile(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_22(const uint8_t *Data, size_t Size) {
    sqlite3 *db;
    sqlite3_stmt *stmt = NULL;
    int rc;

    // Write the input data to a dummy file
    writeDummyFile(Data, Size);

    // Initialize database connection
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        return 0;
    }

    // Prepare statement
    rc = sqlite3_prepare_v2(db, (const char *)Data, Size, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    // Step through the statement
    rc = sqlite3_step(stmt);

    // Retrieve column text if a row is available
    if (rc == SQLITE_ROW) {
        const unsigned char *text = sqlite3_column_text(stmt, 0);
        if (text) {
            // Use sqlite3_mprintf to format a string
            char *formatted = sqlite3_mprintf("Column text: %s", text);
            if (formatted) {
                // Create a dynamic string object
                sqlite3_str *str = sqlite3_str_new(db);
                if (str) {
                    // Append formatted text to the string
                    sqlite3_str_appendf(str, "First append: %s", formatted);
                    sqlite3_str_appendf(str, "Second append: %s", formatted);

                    // Free the dynamic string object
                    sqlite3_free(sqlite3_str_finish(str));
                }
                // Free the formatted string
                sqlite3_free(formatted);
            }
        }
    }

    // Finalize the statement
    sqlite3_finalize(stmt);

    // Close the database
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

        LLVMFuzzerTestOneInput_22(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    