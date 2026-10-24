// This fuzz driver is generated for library htslib, aiming to fuzz the following functions:
// hopen at hfile.c:1304:8 in hfile.h
// hgets at hfile.c:291:7 in hfile.h
// hclose at hfile.c:490:5 in hfile.h
// hputs at hfile.h:262:19 in hfile.h
// hgetln at hfile.h:196:1 in hfile.h
// hgetc at hfile.h:163:19 in hfile.h
// hgetdelim at hfile.c:241:9 in hfile.h
// hclearerr at hfile.h:140:20 in hfile.h
// hclose at hfile.c:490:5 in hfile.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "hfile.h"

static hFILE *create_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) return NULL;
    fwrite(Data, 1, Size, file);
    fclose(file);

    return hopen("./dummy_file", "rb");
}

int LLVMFuzzerTestOneInput_85(const uint8_t *Data, size_t Size) {
    if (Size < 2) return 0;

    hFILE *hfile = create_dummy_file(Data, Size);
    if (!hfile) return 0;

    char buffer[256];
    int result;
    ssize_t sresult;

    // Test hgets
    if (Size > 1) {
        memset(buffer, 0, sizeof(buffer));
        hgets(buffer, sizeof(buffer), hfile);
    }

    // Ensure the input data is null-terminated before using it with hputs
    char *null_terminated_data = (char *)malloc(Size + 1);
    if (!null_terminated_data) {
        hclose(hfile);
        return 0;
    }
    memcpy(null_terminated_data, Data, Size);
    null_terminated_data[Size] = '\0';

    // Test hputs
    if (Size > 2) {
        hputs(null_terminated_data, hfile);
    }

    // Test hgetln
    if (Size > 3) {
        memset(buffer, 0, sizeof(buffer));
        hgetln(buffer, sizeof(buffer), hfile);
    }

    // Test hgetc
    if (Size > 4) {
        result = hgetc(hfile);
    }

    // Test hgetdelim
    if (Size > 5) {
        memset(buffer, 0, sizeof(buffer));
        sresult = hgetdelim(buffer, sizeof(buffer), '\n', hfile);
    }

    // Test hclearerr
    if (Size > 6) {
        hclearerr(hfile);
    }

    free(null_terminated_data);
    hclose(hfile);
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

    LLVMFuzzerTestOneInput_85(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
