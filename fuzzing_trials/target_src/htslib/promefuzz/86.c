// This fuzz driver is generated for library htslib, aiming to fuzz the following functions:
// hts_bin_maxpos at hts.h:1557:25 in hts.h
// hts_reg2bin at hts.h:1516:19 in hts.h
// hfile_list_plugins at hfile.c:1245:5 in hfile.h
// hts_bin_level at hts.h:1525:19 in hts.h
// hts_bin_bot at hts.h:1550:19 in hts.h
// ed_is_big at hts.h:1567:19 in hts.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include "hfile.h"
#include "hts.h"

// Dummy file path
#define DUMMY_FILE "./dummy_file"

int LLVMFuzzerTestOneInput_86(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Fuzzing hts_bin_maxpos
    if (Size >= 2) {
        int min_shift = Data[0];
        int n_lvls = Data[1];
        hts_pos_t max_pos = hts_bin_maxpos(min_shift, n_lvls);
    }

    // Fuzzing hts_reg2bin
    if (Size >= 18) { // Ensure enough data for two hts_pos_t and other parameters
        hts_pos_t beg = *(hts_pos_t *)&Data[0];
        hts_pos_t end = *(hts_pos_t *)&Data[8];
        if (beg < end) {
            int min_shift = Data[16];
            int n_lvls = Data[17];
            int bin = hts_reg2bin(beg, end, min_shift, n_lvls);
        }
    }

    // Fuzzing hfile_list_plugins
    const char *plist[10];
    int nplugins = 10;
    int total_plugins = hfile_list_plugins(plist, &nplugins);

    // Fuzzing hts_bin_level
    if (Size >= 19) {
        int bin = Data[18];
        int level = hts_bin_level(bin);
    }

    // Fuzzing hts_bin_bot
    if (Size >= 20) {
        int bin = Data[18];
        int n_lvls = Data[19];
        int offset = hts_bin_bot(bin, n_lvls);
    }

    // Fuzzing ed_is_big
    int is_big_endian = ed_is_big();

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

    LLVMFuzzerTestOneInput_86(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
