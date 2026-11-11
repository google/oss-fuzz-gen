#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_126(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract an hid_t
    if (size < sizeof(hid_t)) {
        return 0;
    }

    // Extract hid_t from data
    hid_t object_id = *(hid_t *)data;

    // Initialize H5A_info_t structure
    H5A_info_t ainfo;

    // Call the function-under-test
    herr_t status = H5Aget_info(object_id, &ainfo);

    // The status can be checked here, but since this is fuzzing, we are mainly
    // interested in any crashes or memory corruptions that occur.

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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_126(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
