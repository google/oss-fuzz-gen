// This fuzz driver is generated for library htslib, aiming to fuzz the following functions:
// hopen at hfile.c:1304:8 in hfile.h
// hwrite at hfile.h:280:1 in hfile.h
// hclose_abruptly at hfile.c:507:6 in hfile.h
// hread at hfile.h:235:1 in hfile.h
// hclose_abruptly at hfile.c:507:6 in hfile.h
// hwrite2 at hfile.c:400:9 in hfile.h
// hclose_abruptly at hfile.c:507:6 in hfile.h
// hputs at hfile.h:262:19 in hfile.h
// hclose_abruptly at hfile.c:507:6 in hfile.h
// hgetln at hfile.h:196:1 in hfile.h
// hclose_abruptly at hfile.c:507:6 in hfile.h
// hclose_abruptly at hfile.c:507:6 in hfile.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "hfile.h"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_41(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    write_dummy_file(Data, Size);

    hFILE *fp = hopen("./dummy_file", "r+");
    if (!fp) return 0;

    char buffer[1024];
    ssize_t result;

    // Test hwrite
    result = hwrite(fp, Data, Size);
    if (result < 0) {
        hclose_abruptly(fp);
        return 0;
    }

    // Test hread
    result = hread(fp, buffer, sizeof(buffer));
    if (result < 0) {
        hclose_abruptly(fp);
        return 0;
    }

    // Test hwrite2
    result = hwrite2(fp, Data, Size, 0);
    if (result < 0) {
        hclose_abruptly(fp);
        return 0;
    }

    // Test hputs
    if (hputs("test string", fp) == EOF) {
        hclose_abruptly(fp);
        return 0;
    }

    // Test hgetln
    result = hgetln(buffer, sizeof(buffer), fp);
    if (result < 0) {
        hclose_abruptly(fp);
        return 0;
    }

    // Cleanup
    hclose_abruptly(fp);
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

    LLVMFuzzerTestOneInput_41(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
