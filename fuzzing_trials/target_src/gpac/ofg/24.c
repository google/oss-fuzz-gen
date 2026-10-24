#include <stdint.h>
#include <stdlib.h>
#include <gpac/isomedia.h>
#include <gpac/tools.h> // Include for Bool type

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_24(const uint8_t *data, size_t size) {
    if (data == NULL || size == 0) {
        return 0; // Return immediately if data is null or size is zero
    }

    // Initialize the parameters for the function call
    GF_ISOFile *file = gf_isom_open(NULL, GF_ISOM_OPEN_READ, NULL); // Open a new ISO file structure
    if (!file) {
        return 0; // Return if file opening fails
    }

    Bool root_meta = (Bool)(data[0] % 2); // Use first byte to determine true/false
    u32 track_num = (size > 1) ? data[1] : 1; // Use second byte or default to 1
    u32 to_id = (size > 2) ? data[2] : 1; // Use third byte or default to 1
    u32 type = (size > 3) ? data[3] : 1; // Use fourth byte or default to 1

    // Call the function-under-test
    gf_isom_meta_item_has_ref(file, root_meta, track_num, to_id, type);

    // Close the ISO file structure
    gf_isom_close(file);

    return 0;
}

#ifdef __cplusplus
}
#endif
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
