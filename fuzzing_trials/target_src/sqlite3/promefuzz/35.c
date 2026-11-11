// This fuzz driver is generated for library sqlite3, aiming to fuzz the following functions:
// sqlite3_compileoption_used at sqlite3.c:176156:16 in sqlite3.h
// sqlite3_open_v2 at sqlite3.c:174702:16 in sqlite3.h
// sqlite3_close at sqlite3.c:172361:16 in sqlite3.h
// sqlite3_close at sqlite3.c:172361:16 in sqlite3.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sqlite3.h>

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_35(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Ensure null-termination for optionName
    char *optionName = (char *)malloc(Size + 1);
    if (!optionName) return 0;
    memcpy(optionName, Data, Size);
    optionName[Size] = '\0';

    // Step 1: Invoke sqlite3_compileoption_used
    int optionUsed = sqlite3_compileoption_used(optionName);

    // Clean up optionName
    free(optionName);

    // Step 2: Prepare for sqlite3_open_v2
    sqlite3 *db = NULL;
    const char *filename = "./dummy_file";
    int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE;
    const char *vfs = NULL;

    // Write data to the dummy file
    write_dummy_file(Data, Size);

    // Step 3: Invoke sqlite3_open_v2
    int rc = sqlite3_open_v2(filename, &db, flags, vfs);
    if (rc != SQLITE_OK) {
        // If opening the database failed, clean up and exit
        if (db) {
            sqlite3_close(db);
        }
        return 0;
    }

    // Step 4: Invoke sqlite3_close
    rc = sqlite3_close(db);
    if (rc != SQLITE_OK) {
        // Handle the error if closing failed
        return 0;
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

        if(size < 1 + 1)
            exit(0);

        data = (uint8_t *)malloc((size_t)size);
        if(data == NULL)
            exit(0);

        if(fread(data, (size_t)size, 1, f) != 1)
            exit(0);

        LLVMFuzzerTestOneInput_35(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    