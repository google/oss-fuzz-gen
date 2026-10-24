#include <stdint.h>
#include <stddef.h>
#include <gpac/isomedia.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_61(const uint8_t *data, size_t size) {
    // Ensure the data is null-terminated for safe string operations
    char *temp_data = (char *)malloc(size + 1);
    if (!temp_data) {
        return 0; // Exit if memory allocation fails
    }
    memcpy(temp_data, data, size);
    temp_data[size] = '\0';

    // Initialize variables
    GF_ISOFile *file = gf_isom_open(temp_data, GF_ISOM_OPEN_READ, NULL);
    free(temp_data); // Free the temporary data after use
    if (!file) {
        return 0; // Exit if file cannot be opened
    }

    // Set parameters for the function call
    Bool root_meta = GF_FALSE;
    u32 track_num = 1;  // Assuming a valid non-zero track number
    u32 from_id = 1;    // Assuming a valid non-zero ID
    u32 type = 1;       // Assuming a valid non-zero type

    // Call the function-under-test
    gf_isom_meta_get_item_ref_count(file, root_meta, track_num, from_id, type);

    // Clean up
    gf_isom_close(file);

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

    LLVMFuzzerTestOneInput_61(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
