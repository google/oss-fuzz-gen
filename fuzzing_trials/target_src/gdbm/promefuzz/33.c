// This fuzz driver is generated for library gdbm, aiming to fuzz the following functions:
// gdbm_open at gdbmopen.c:791:1 in gdbm.h
// gdbm_store at gdbmstore.c:39:1 in gdbm.h
// gdbm_delete at gdbmdelete.c:29:1 in gdbm.h
// gdbm_convert at gdbmopen.c:933:1 in gdbm.h
// gdbm_last_syserr at gdbmerrno.c:67:1 in gdbm.h
// gdbm_sync at gdbmsync.c:459:1 in gdbm.h
// gdbm_exists at gdbmexists.c:28:1 in gdbm.h
// gdbm_close at gdbmclose.c:28:1 in gdbm.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <gdbm.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    int fd = open("./dummy_file", O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd != -1) {
        write(fd, Data, Size);
        close(fd);
    }
}

int LLVMFuzzerTestOneInput_33(const uint8_t *Data, size_t Size) {
    if (Size < 10) return 0;

    // Prepare dummy file
    write_dummy_file(Data, Size);

    // Open GDBM database
    GDBM_FILE dbf = gdbm_open("./dummy_file", 512, GDBM_WRCREAT, 0600, NULL);
    if (dbf == NULL) return 0;

    // Prepare key and value
    datum key, value;
    key.dptr = (char *)Data;
    key.dsize = Size / 2;
    value.dptr = (char *)(Data + Size / 2);
    value.dsize = Size - Size / 2;

    // Fuzz gdbm_store
    gdbm_store(dbf, key, value, GDBM_INSERT);

    // Fuzz gdbm_delete
    gdbm_delete(dbf, key);

    // Fuzz gdbm_convert
    gdbm_convert(dbf, 0);

    // Fuzz gdbm_last_syserr
    gdbm_last_syserr(dbf);

    // Fuzz gdbm_sync
    gdbm_sync(dbf);

    // Fuzz gdbm_exists
    gdbm_exists(dbf, key);

    // Close the database
    gdbm_close(dbf);

    return 0;
}