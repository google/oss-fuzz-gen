// This fuzz driver is generated for library htslib, aiming to fuzz the following functions:
// hfile_has_plugin at hfile.c:1281:5 in hfile.h
// hopen at hfile.c:1304:8 in hfile.h
// hts_hopen at hts.c:1463:10 in hts.h
// hts_close at hts.c:1639:5 in hts.h
// hclose at hfile.c:490:5 in hfile.h
// hopen at hfile.c:1304:8 in hfile.h
// hgets at hfile.c:291:7 in hfile.h
// hclose at hfile.c:490:5 in hfile.h
// hopen at hfile.c:1304:8 in hfile.h
// hread at hfile.h:235:1 in hfile.h
// hclose at hfile.c:490:5 in hfile.h
// hopen at hfile.c:1304:8 in hfile.h
// hgetln at hfile.h:196:1 in hfile.h
// hclose at hfile.c:490:5 in hfile.h
// hts_readlist at hts.c:2060:8 in hts.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <hfile.h>
#include <hts.h>

static void fuzz_hgets(const uint8_t *Data, size_t Size) {
    if (Size < 2) return;

    FILE *file = fopen("./dummy_file", "wb");
    if (!file) return;
    fwrite(Data, 1, Size, file);
    fclose(file);

    file = fopen("./dummy_file", "rb");
    if (!file) return;

    hFILE *hfile = hopen("dummy_file", "rb");
    if (!hfile) {
        fclose(file);
        return;
    }

    char buffer[256];
    hgets(buffer, sizeof(buffer), hfile);

    hclose(hfile);
    fclose(file);
}

static void fuzz_hread(const uint8_t *Data, size_t Size) {
    if (Size < 2) return;

    FILE *file = fopen("./dummy_file", "wb");
    if (!file) return;
    fwrite(Data, 1, Size, file);
    fclose(file);

    file = fopen("./dummy_file", "rb");
    if (!file) return;

    hFILE *hfile = hopen("dummy_file", "rb");
    if (!hfile) {
        fclose(file);
        return;
    }

    char buffer[256];
    hread(hfile, buffer, sizeof(buffer));

    hclose(hfile);
    fclose(file);
}

static void fuzz_hgetln(const uint8_t *Data, size_t Size) {
    if (Size < 2) return;

    FILE *file = fopen("./dummy_file", "wb");
    if (!file) return;
    fwrite(Data, 1, Size, file);
    fclose(file);

    file = fopen("./dummy_file", "rb");
    if (!file) return;

    hFILE *hfile = hopen("dummy_file", "rb");
    if (!hfile) {
        fclose(file);
        return;
    }

    char buffer[256];
    hgetln(buffer, sizeof(buffer), hfile);

    hclose(hfile);
    fclose(file);
}

static void fuzz_hts_readlist(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    int n;
    char *input = (char *)malloc(Size + 1);
    if (!input) return;
    memcpy(input, Data, Size);
    input[Size] = '\0';

    char **list = hts_readlist(input, 0, &n);
    if (list) {
        for (int i = 0; i < n; ++i) {
            free(list[i]);
        }
        free(list);
    }
    free(input);
}

static void fuzz_hfile_has_plugin(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    char *plugin_name = (char *)malloc(Size + 1);
    if (!plugin_name) return;
    memcpy(plugin_name, Data, Size);
    plugin_name[Size] = '\0';

    hfile_has_plugin(plugin_name);

    free(plugin_name);
}

static void fuzz_hts_hopen(const uint8_t *Data, size_t Size) {
    if (Size < 2) return;

    FILE *file = fopen("./dummy_file", "wb");
    if (!file) return;
    fwrite(Data, 1, Size, file);
    fclose(file);

    file = fopen("./dummy_file", "rb");
    if (!file) return;

    hFILE *hfile = hopen("dummy_file", "rb");
    if (!hfile) {
        fclose(file);
        return;
    }

    htsFile *hts_file = hts_hopen(hfile, "dummy_file", "r");
    if (hts_file) {
        hts_close(hts_file);
    }

    hclose(hfile);
    fclose(file);
}

int LLVMFuzzerTestOneInput_28(const uint8_t *Data, size_t Size) {
    fuzz_hgets(Data, Size);
    fuzz_hread(Data, Size);
    fuzz_hgetln(Data, Size);
    fuzz_hts_readlist(Data, Size);
    fuzz_hfile_has_plugin(Data, Size);
    fuzz_hts_hopen(Data, Size);
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

    LLVMFuzzerTestOneInput_28(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
