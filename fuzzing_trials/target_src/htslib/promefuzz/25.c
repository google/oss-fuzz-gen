// This fuzz driver is generated for library htslib, aiming to fuzz the following functions:
// hts_open at hts.c:991:10 in hts.h
// hts_opt_apply at hts.c:1247:5 in hts.h
// hts_check_EOF at hts.c:2203:5 in hts.h
// hts_close at hts.c:1639:5 in hts.h
// hts_set_filter_expression at hts.c:1967:5 in hts.h
// hts_close at hts.c:1639:5 in hts.h
// hts_flush at hts.c:1712:5 in hts.h
// hts_close at hts.c:1639:5 in hts.h
// hts_set_fai_filename at hts.c:1951:5 in hts.h
// hts_close at hts.c:1639:5 in hts.h
// hts_close at hts.c:1639:5 in hts.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hts.h>

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

static htsFile* open_hts_file() {
    return hts_open("./dummy_file", "r");
}

static void apply_hts_options(htsFile *fp) {
    hts_opt opts = {
        .arg = strdup("CRAM_OPT_USE_BZIP2"),
        .opt = CRAM_OPT_USE_BZIP2,
        .val.i = 1,
        .next = NULL
    };
    hts_opt_apply(fp, &opts);
    free(opts.arg);
}

int LLVMFuzzerTestOneInput_25(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Write data to a dummy file
    write_dummy_file(Data, Size);

    // Open the htsFile
    htsFile *fp = open_hts_file();
    if (!fp) return 0;

    // Test hts_check_EOF
    int eof_check = hts_check_EOF(fp);
    if (eof_check < 0) {
        hts_close(fp);
        return 0;
    }

    // Test hts_set_filter_expression
    const char *filter_expr = Size > 10 ? (const char *)Data : NULL;
    int filter_result = hts_set_filter_expression(fp, filter_expr);
    if (filter_result < 0) {
        hts_close(fp);
        return 0;
    }

    // Test hts_flush
    int flush_result = hts_flush(fp);
    if (flush_result < 0) {
        hts_close(fp);
        return 0;
    }

    // Apply some options
    apply_hts_options(fp);

    // Test hts_set_fai_filename
    const char *fai_filename = Size > 20 ? (const char *)(Data + 10) : NULL;
    int fai_result = hts_set_fai_filename(fp, fai_filename);
    if (fai_result < 0) {
        hts_close(fp);
        return 0;
    }

    // Close the file
    int close_result = hts_close(fp);
    if (close_result < 0) {
        return 0;
    }

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

    LLVMFuzzerTestOneInput_25(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
