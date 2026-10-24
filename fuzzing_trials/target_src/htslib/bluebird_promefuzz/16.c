#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "htslib/hts.h"
#include "htslib/sam.h"

static void initialize_htsFormat(htsFormat *format) {
    if (format) {
        memset(format, 0, sizeof(htsFormat));
        format->specific = NULL;
    }
}

static void test_hts_parse_opt_list(const uint8_t *Data, size_t Size) {
    htsFormat format;
    initialize_htsFormat(&format);
    
    if (Size > 0) {
        char *input = (char *)malloc(Size + 1);
        if (input) {
            memcpy(input, Data, Size);
            input[Size] = '\0';
            hts_parse_opt_list(&format, input);
            free(input);
        }
    }
}

static void test_hts_open_format(const uint8_t *Data, size_t Size) {
    htsFormat format;
    initialize_htsFormat(&format);

    FILE *dummy_file = fopen("./dummy_file", "w+");
    if (!dummy_file) {
        return;
    }
    fwrite(Data, 1, Size, dummy_file);
    fclose(dummy_file);

    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 1 of hts_open_format
    htsFile *file = hts_open_format("./dummy_file", (const char *)"w", &format);
    // End mutation: Producer.REPLACE_ARG_MUTATOR
    if (file) {
        hts_close(file);
    }
}

static void test_hts_format_file_extension(const uint8_t *Data, size_t Size) {
    htsFormat format;
    initialize_htsFormat(&format);

    if (Size > 0) {
        char *input = (char *)malloc(Size + 1);
        if (input) {
            memcpy(input, Data, Size);
            input[Size] = '\0';
            hts_parse_format(&format, input);
            const char *extension = hts_format_file_extension(&format);
            (void)extension; // Suppress unused variable warning
            free(input);
        }
    }
}

static void test_hts_format_description(const uint8_t *Data, size_t Size) {
    htsFormat format;
    initialize_htsFormat(&format);

    if (Size > 0) {
        char *input = (char *)malloc(Size + 1);
        if (input) {
            memcpy(input, Data, Size);
            input[Size] = '\0';
            hts_parse_format(&format, input);
            char *description = hts_format_description(&format);
            if (description) {
                free(description);
            }
            free(input);
        }
    }
}

static void test_sam_open_mode(const uint8_t *Data, size_t Size) {
    char mode[10] = {0}; // Sufficient size for mode string
    if (Size > 0) {
        char *input = (char *)malloc(Size + 1);
        if (input) {
            memcpy(input, Data, Size);
            input[Size] = '\0';
            sam_open_mode(mode, "dummy_file", input);
            free(input);
        }
    }
}

static void test_hts_parse_format(const uint8_t *Data, size_t Size) {
    htsFormat format;
    initialize_htsFormat(&format);

    if (Size > 0) {
        char *input = (char *)malloc(Size + 1);
        if (input) {
            memcpy(input, Data, Size);
            input[Size] = '\0';
            hts_parse_format(&format, input);
            free(input);
        }
    }
}

int LLVMFuzzerTestOneInput_16(const uint8_t *Data, size_t Size) {
    test_hts_parse_opt_list(Data, Size);
    test_hts_open_format(Data, Size);
    test_hts_format_file_extension(Data, Size);
    test_hts_format_description(Data, Size);
    test_sam_open_mode(Data, Size);
    test_hts_parse_format(Data, Size);
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

    LLVMFuzzerTestOneInput_16(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
