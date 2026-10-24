// This fuzz driver is generated for library gdbm, aiming to fuzz the following functions:
// gdbm_open at gdbmopen.c:791:1 in gdbm.h
// gdbm_bucket_count at gdbmcount.c:44:1 in gdbm.h
// gdbm_avail_verify at avail.c:287:1 in gdbm.h
// gdbm_get_cache_stats at bucket.c:773:1 in gdbm.h
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
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_42(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    write_dummy_file(Data, Size);

    GDBM_FILE dbf = gdbm_open("./dummy_file", 512, GDBM_WRCREAT, 0666, NULL);
    if (!dbf) {
        return 0;
    }

    size_t bucket_count = 0;
    gdbm_bucket_count(dbf, &bucket_count);

    gdbm_avail_verify(dbf);

    size_t access_count = 0, cache_hits = 0, cache_count = 0;
    struct gdbm_cache_stat cache_stats[10];
    gdbm_get_cache_stats(dbf, &access_count, &cache_hits, &cache_count, cache_stats, 10);

    int last_syserr = gdbm_last_syserr(dbf);

    gdbm_sync(dbf);

    datum key;
    if (Size > sizeof(datum)) {
        memcpy(&key, Data, sizeof(datum));
        gdbm_exists(dbf, key);
    }

    gdbm_close(dbf);
    return 0;
}