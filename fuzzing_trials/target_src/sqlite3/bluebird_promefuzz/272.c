#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdint.h>
#include "sqlite3.h"

static void invoke_sqlite3_libversion() {
    const char *version = sqlite3_libversion();
    (void)version; // Use the version in some way to avoid compiler warnings
}

static void invoke_sqlite3_sourceid() {
    const char *sourceid = sqlite3_sourceid();
    (void)sourceid; // Use the sourceid in some way to avoid compiler warnings
}

static void invoke_sqlite3_config() {
    int rc;
    rc = sqlite3_config(SQLITE_CONFIG_SINGLETHREAD);
    if (rc != SQLITE_OK) return;
    rc = sqlite3_config(SQLITE_CONFIG_MULTITHREAD);
    if (rc != SQLITE_OK) return;
    rc = sqlite3_config(SQLITE_CONFIG_SERIALIZED);
    if (rc != SQLITE_OK) return;
    rc = sqlite3_config(SQLITE_CONFIG_URI, 1);
    if (rc != SQLITE_OK) return;
    rc = sqlite3_config(SQLITE_CONFIG_MEMSTATUS, 1);
    if (rc != SQLITE_OK) return;
    rc = sqlite3_config(SQLITE_CONFIG_LOG, NULL, NULL);
    if (rc != SQLITE_OK) return;
}

static void invoke_sqlite3_initialize() {
    int rc = sqlite3_initialize();
    (void)rc; // Use the rc in some way to avoid compiler warnings
}

static void invoke_sqlite3_vfs_find() {
    sqlite3_vfs *vfs = sqlite3_vfs_find(NULL);
    (void)vfs; // Use the vfs in some way to avoid compiler warnings
}

int LLVMFuzzerTestOneInput_272(const uint8_t *Data, size_t Size) {
    // Step 1: Invoke sqlite3_libversion
    invoke_sqlite3_libversion();

    // Step 2: Invoke sqlite3_sourceid
    invoke_sqlite3_sourceid();

    // Step 3: Invoke sqlite3_config multiple times
    invoke_sqlite3_config();

    // Step 4: Invoke sqlite3_initialize
    invoke_sqlite3_initialize();

    // Step 5: Invoke sqlite3_vfs_find
    invoke_sqlite3_vfs_find();

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

    LLVMFuzzerTestOneInput_272(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
