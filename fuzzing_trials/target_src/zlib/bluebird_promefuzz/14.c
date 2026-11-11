#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "zlib.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static gzFile create_gz_file() {
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) {
        return NULL;
    }
    fclose(file);
    return gzopen("./dummy_file", "wb");
}

static void write_to_gz_file(gzFile file, const uint8_t *Data, size_t Size) {
    if (file && Data && Size > 0) {
        // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 2 of gzwrite
        gzwrite(file, Data, Z_DEFAULT_COMPRESSION);
        // End mutation: Producer.REPLACE_ARG_MUTATOR
    }
}

static void check_gz_error(gzFile file) {
    if (file) {
        int errnum;
        gzerror(file, &errnum);
    }
}

static void close_gz_file(gzFile file) {
    if (file) {
        gzclose(file);
    }
}

int LLVMFuzzerTestOneInput_14(const uint8_t *Data, size_t Size) {
    gzFile file = create_gz_file();
    if (!file) {
        return 0;
    }

    write_to_gz_file(file, Data, Size);
    check_gz_error(file);
    close_gz_file(file);

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

    LLVMFuzzerTestOneInput_14(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
