#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "htslib/hfile.h"
#include "htslib/hts.h"

static void fuzz_hts_detect_format2(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) {
        return;
    }
    fwrite(Data, 1, Size, file);
    fclose(file);

    file = fopen("./dummy_file", "rb");
    if (!file) {
        return;
    }

    hFILE *hfile = hopen(file, "rb");
    if (!hfile) {
        fclose(file);
        return;
    }

    htsFormat fmt;
    hts_detect_format2(hfile, "./dummy_file", &fmt);

    hclose(hfile);
    fclose(file);
}

static void fuzz_hgets(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) {
        return;
    }
    fwrite(Data, 1, Size, file);
    fclose(file);

    file = fopen("./dummy_file", "rb");
    if (!file) {
        return;
    }

    hFILE *hfile = hopen(file, "rb");
    if (!hfile) {
        fclose(file);
        return;
    }

    char buffer[1024];
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 1 of hgets
    hgets(buffer, HTS_IDX_NONE, hfile);
    // End mutation: Producer.REPLACE_ARG_MUTATOR

    hclose(hfile);
    fclose(file);
}

static void fuzz_hts_parse_opt_list(const uint8_t *Data, size_t Size) {
    char *str = malloc(Size + 1);
    if (!str) {
        return;
    }
    memcpy(str, Data, Size);
    str[Size] = '\0';

    htsFormat fmt;
    hts_parse_opt_list(&fmt, str);

    free(str);
}

static void fuzz_hts_readlist(const uint8_t *Data, size_t Size) {
    char *str = malloc(Size + 1);
    if (!str) {
        return;
    }
    memcpy(str, Data, Size);
    str[Size] = '\0';

    int n;
    char **list = hts_readlist(str, 0, &n);
    if (list) {
        for (int i = 0; i < n; ++i) {
            free(list[i]);
        }
        free(list);
    }

    free(str);
}

static void fuzz_hfile_has_plugin(const uint8_t *Data, size_t Size) {
    char *str = malloc(Size + 1);
    if (!str) {
        return;
    }
    memcpy(str, Data, Size);
    str[Size] = '\0';

    hfile_has_plugin(str);

    free(str);
}

static void fuzz_hts_features() {
    hts_features();
}

int LLVMFuzzerTestOneInput_75(const uint8_t *Data, size_t Size) {
    fuzz_hts_detect_format2(Data, Size);
    fuzz_hgets(Data, Size);
    fuzz_hts_parse_opt_list(Data, Size);
    fuzz_hts_readlist(Data, Size);
    fuzz_hfile_has_plugin(Data, Size);
    fuzz_hts_features();

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

    LLVMFuzzerTestOneInput_75(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
