#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "htslib/hfile.h"
#include "htslib/sam.h"
#include "htslib/hts.h"

static char *create_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *fp = fopen("./dummy_file", "wb");
    if (!fp) {
        return NULL;
    }
    fwrite(Data, 1, Size, fp);
    fclose(fp);
    return "./dummy_file";
}

int LLVMFuzzerTestOneInput_24(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Create a dummy file with the input data
    const char *dummy_filename = create_dummy_file(Data, Size);
    if (!dummy_filename) {
        return 0;
    }

    // Fuzz hts_open_format
    htsFormat fmt;
    memset(&fmt, 0, sizeof(htsFormat));
    fmt.specific = NULL; // No specific options needed
    htsFile *file = hts_open_format(dummy_filename, "r", &fmt);
    if (file) {
        hts_close(file);
    }

    // Fuzz sam_open_mode_opts
    char *mode_opts = sam_open_mode_opts(dummy_filename, "r", NULL);
    if (mode_opts) {
        free(mode_opts);
    }

    // Fuzz sam_index_build
    sam_index_build(dummy_filename, 0);

    // Fuzz sam_open_mode
    char mode[8];
    sam_open_mode(mode, dummy_filename, NULL);

    // Fuzz haddextension

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sam_open_mode to sam_index_load

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from sam_open_mode to sam_hdr_pg_id
    sam_hdr_t xwigjesk;
    memset(&xwigjesk, 0, sizeof(xwigjesk));
    sam_hdr_incr_ref(&xwigjesk);
    // Ensure dataflow is valid (i.e., non-null)
    if (!mode) {
    	return 0;
    }
    const char* ret_sam_hdr_pg_id_uusjo = sam_hdr_pg_id(&xwigjesk, mode);
    if (ret_sam_hdr_pg_id_uusjo == NULL){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    htsFile rgiswpne;
    memset(&rgiswpne, 0, sizeof(rgiswpne));
    int ret_hts_check_EOF_dwktv = hts_check_EOF(&rgiswpne);
    if (ret_hts_check_EOF_dwktv < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!mode) {
    	return 0;
    }
    hts_idx_t* ret_sam_index_load_dmxuc = sam_index_load(&rgiswpne, mode);
    if (ret_sam_index_load_dmxuc == NULL){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    kstring_t buffer;
    memset(&buffer, 0, sizeof(kstring_t));
    char *modified_filename = haddextension(&buffer, dummy_filename, 0, ".csi");
    if (modified_filename) {
        free(buffer.s);
    }

    // Fuzz hts_hopen
    hFILE *hfile = hopen(dummy_filename, "rb");
    if (hfile) {
        htsFile *hfile_open = hts_hopen(hfile, dummy_filename, "r");
        if (hfile_open) {
            hts_close(hfile_open);
        } else {
            hclose(hfile);  // Close only if hts_hopen fails
        }
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

    LLVMFuzzerTestOneInput_24(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
