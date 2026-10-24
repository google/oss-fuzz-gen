#include <gdbm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int LLVMFuzzerTestOneInput_188(const uint8_t *data, size_t size) {
    const char *src_db_name = "/tmp/src_db.gdbm";
    const char *dest_db_name = "/tmp/dest_db.gdbm";

    // Create source database
    GDBM_FILE src_db = gdbm_open((char *)src_db_name, 512, GDBM_WRCREAT | GDBM_NOLOCK, 0666, NULL);
    if (!src_db) {
        fprintf(stderr, "Failed to open source database\n");
        return 0;
    }

    // Create destination database
    GDBM_FILE dest_db = gdbm_open((char *)dest_db_name, 512, GDBM_WRCREAT | GDBM_NOLOCK, 0666, NULL);
    if (!dest_db) {
        fprintf(stderr, "Failed to open destination database\n");
        gdbm_close(src_db);
        return 0;
    }

    // Write the fuzz data to the source database
    datum key = { (char *)"key", 3 };
    datum value = { (char *)data, (int)size };
    if (gdbm_store(src_db, key, value, GDBM_REPLACE) != 0) {
        fprintf(stderr, "Failed to store data in source database\n");
        gdbm_close(src_db);
        gdbm_close(dest_db);
        return 0;
    }

    // Call the function-under-test
    gdbm_copy_meta(src_db, dest_db);

    // Clean up
    gdbm_close(src_db);
    gdbm_close(dest_db);
    unlink(src_db_name);
    unlink(dest_db_name);

    return 0;
}