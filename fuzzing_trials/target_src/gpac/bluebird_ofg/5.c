#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include "/src/gpac/include/gpac/isomedia.h"
#include <string.h>
#include <stdio.h> // Include stdio.h for file operations

int LLVMFuzzerTestOneInput_5(const uint8_t *data, size_t size) {
    // Ensure that the size is large enough to extract values
    if (size < sizeof(uint32_t) * 2 + 1) {
        return 0;
    }

    // Create a temporary file to work with
    const char *temp_filename = "dummy.mp4";
    FILE *temp_file = fopen(temp_filename, "wb");
    if (!temp_file) {
        return 0;
    }

    // Write the input data to the temporary file to ensure it is not empty
    if (fwrite(data, 1, size, temp_file) != size) {
        fclose(temp_file);
        remove(temp_filename);
        return 0;
    }
    fclose(temp_file);

    GF_ISOFile *file = gf_isom_open(temp_filename, GF_ISOM_OPEN_READ_EDIT, NULL); // Use GF_ISOM_OPEN_READ_EDIT
    if (!file) {
        remove(temp_filename);
        return 0;
    }

    // Extract values from the input data
    Bool root_meta = (Bool)(data[0] % 2); // Use the first byte to determine root_meta
    u32 track_num = *(const u32 *)(data + 1); // Use the next 4 bytes for track_num
    u32 item_id = *(const u32 *)(data + 5); // Use the next 4 bytes for item_id

    // Call the function-under-test
    gf_isom_set_meta_primary_item(file, root_meta, track_num, item_id);

    // Clean up
    gf_isom_close(file);
    remove(temp_filename);

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

    LLVMFuzzerTestOneInput_5(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
