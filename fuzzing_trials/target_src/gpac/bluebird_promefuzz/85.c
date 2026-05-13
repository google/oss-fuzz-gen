#include <sys/stat.h>
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
#include "/src/gpac/include/gpac/isomedia.h"

#define DUMMY_FILE "./dummy_file"

// Helper function to write data to a dummy file
static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen(DUMMY_FILE, "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_85(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u64) * 2 + sizeof(Bool) + sizeof(u32)) {
        return 0; // Not enough data to proceed
    }

    // Write the input data to a dummy file
    write_dummy_file(Data, Size);

    // Extract parameters for gf_isom_open_progressive_ex
    u64 start_range = *(u64 *)Data;
    u64 end_range = *(u64 *)(Data + sizeof(u64));
    Bool enable_frag_templates = *(Bool *)(Data + 2 * sizeof(u64));

    GF_ISOFile *isom_file = NULL;
    u64 BytesMissing = 0;
    u32 topBoxType = 0;

    // Call gf_isom_open_progressive_ex
    gf_isom_open_progressive_ex(DUMMY_FILE, start_range, end_range, enable_frag_templates, &isom_file, &BytesMissing, &topBoxType);

    // If a valid ISO file was opened, test additional functions
    if (isom_file) {
        // Extract parameters for gf_isom_open_segment
        const char *segmentFileName = DUMMY_FILE;
        GF_ISOSegOpenMode flags = *(GF_ISOSegOpenMode *)(Data + 2 * sizeof(u64) + sizeof(Bool));

        gf_isom_open_segment(isom_file, segmentFileName, start_range, end_range, flags);

        // Extract parameters for gf_isom_add_chapter
        u32 trackNumber = *(u32 *)(Data + 2 * sizeof(u64) + sizeof(Bool) + sizeof(GF_ISOSegOpenMode));
        u64 timestamp = *(u64 *)(Data + 2 * sizeof(u64) + sizeof(Bool) + sizeof(GF_ISOSegOpenMode) + sizeof(u32));
        char *chapterName = "Chapter 1";

        gf_isom_add_chapter(isom_file, trackNumber, timestamp, chapterName);

        // Extract parameters for gf_isom_refresh_fragmented
        u64 MissingBytes = 0;
        const char *new_location = NULL;

        gf_isom_refresh_fragmented(isom_file, &MissingBytes, new_location);

        // Extract parameters for gf_isom_get_chapter
        u32 Index = *(u32 *)(Data + 2 * sizeof(u64) + sizeof(Bool) + sizeof(GF_ISOSegOpenMode) + sizeof(u32) + sizeof(u64));
        u64 chapter_time = 0;
        const char *name = NULL;

        gf_isom_get_chapter(isom_file, trackNumber, Index, &chapter_time, &name);

        // Clean up
        // Assuming a function gf_isom_close exists for cleanup
        // gf_isom_close(isom_file);
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

    LLVMFuzzerTestOneInput_85(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
