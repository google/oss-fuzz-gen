#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "sqlite3.h"
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

int LLVMFuzzerTestOneInput_178(const uint8_t *Data, size_t Size) {
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

    // Begin mutation: Producer.SPLICE_MUTATOR - Spliced data flow from sqlite3_open to sqlite3_limit using the plateau pool
    // Ensure dataflow is valid (i.e., non-null)
    if (!db) {
    	return 0;
    }
    int ret_sqlite3_limit_aijti = sqlite3_limit(db, SQLITE_LIMIT_LENGTH, (int)Data[0]);
    if (ret_sqlite3_limit_aijti < 0){
    	return 0;
    }
    // End mutation: Producer.SPLICE_MUTATOR
    
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_178(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
