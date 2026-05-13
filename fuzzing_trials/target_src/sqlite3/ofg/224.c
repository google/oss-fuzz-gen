#include <stdint.h>
#include <sqlite3.h>
#include <string.h>

int LLVMFuzzerTestOneInput_224(const uint8_t *data, size_t size) {
  sqlite3 *db;
  sqlite3_stmt *stmt;
  int rc;

  // Initialize SQLite in-memory database
  rc = sqlite3_open(":memory:", &db);
  if (rc != SQLITE_OK) {
    return 0;
  }

  // Prepare a SQL statement from the input data
  const char *sql = (const char *)data;
  rc = sqlite3_prepare_v2(db, sql, size, &stmt, NULL);

  // If the statement is valid, call sqlite3_column_count
  if (rc == SQLITE_OK) {
    int column_count = sqlite3_column_count(stmt);
    (void)column_count; // Use the column_count to avoid unused variable warning

    // Finalize the statement to release resources
    sqlite3_finalize(stmt);
  }

  // Close the database connection
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

    LLVMFuzzerTestOneInput_224(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
