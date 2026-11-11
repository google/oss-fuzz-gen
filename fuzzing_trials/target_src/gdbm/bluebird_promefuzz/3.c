#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "/src/gdbm/src/gdbm.h"
#include <stdio.h>
#include <stdint.h>

static void initialize_gdbm_file(GDBM_FILE *dbf) {
    *dbf = gdbm_open("./dummy_file", 512, GDBM_WRCREAT | GDBM_NEWDB, 0644, NULL);
}

static void cleanup_gdbm_file(GDBM_FILE dbf) {
    if (dbf) {
        gdbm_close(dbf);
    }
}

static void write_dummy_data_to_file(const char *filename) {
    FILE *fp = fopen(filename, "w");
    if (fp) {
        fputs("! Dummy data for testing\nkey1 value1\nkey2 value2\n", fp);
        fclose(fp);
    }
}

int LLVMFuzzerTestOneInput_3(const uint8_t *Data, size_t Size) {
    GDBM_FILE dbf;
    initialize_gdbm_file(&dbf);

    FILE *dummy_fp = fopen("./dummy_file", "w+");
    if (!dummy_fp) {
        cleanup_gdbm_file(dbf);
        return 0;
    }

    write_dummy_data_to_file("./dummy_file");

    // Fuzz gdbm_dump_to_file
    gdbm_dump_to_file(dbf, dummy_fp, Data[0] % 2);

    // Fuzz gdbm_import_from_file
    rewind(dummy_fp);
    gdbm_import_from_file(dbf, dummy_fp, Data[0] % 2);

    // Fuzz gdbm_last_errno
    gdbm_last_errno(dbf);

    // Fuzz gdbm_export_to_file
    gdbm_export_to_file(dbf, dummy_fp);

    // Fuzz gdbm_export
    gdbm_export(dbf, "./dummy_file", GDBM_WRCREAT, 0644);

    // Fuzz gdbm_load_from_file
    unsigned long line = 0;
    gdbm_load_from_file(&dbf, dummy_fp, Data[0] % 2, 0, &line);

    fclose(dummy_fp);
    cleanup_gdbm_file(dbf);

    return 0;
}