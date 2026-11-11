#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/gpac/include/gpac/isomedia.h"

int LLVMFuzzerTestOneInput_56(const uint8_t *data, size_t size) {
    // Ensure that the size of data is sufficient to extract meaningful values
    if (size < sizeof(uint32_t) * 3 + 1) {
        return 0;
    }

    // Create a temporary file to hold the input data
    char filename[] = "/tmp/fuzz_inputXXXXXX";
    int fd = mkstemp(filename);
    if (fd == -1) {
        return 0;
    }
    write(fd, data, size);
    close(fd);

    // Initialize variables
    GF_ISOFile *file = gf_isom_open(filename, GF_ISOM_OPEN_READ, NULL);
    if (!file) {
        remove(filename);
        return 0;
    }

    // Extract values from data
    Bool root_meta = (Bool)(data[0] % 2); // Extract a Bool value
    uint32_t track_num = *((uint32_t *)(data + 1)) % 100; // Extract a uint32_t value
    uint32_t to_id = *((uint32_t *)(data + 5)) % 100; // Extract a uint32_t value
    uint32_t type = *((uint32_t *)(data + 9)) % 100; // Extract a uint32_t value

    // Call the function-under-test
    gf_isom_meta_item_has_ref(file, root_meta, track_num, to_id, type);

    // Clean up
    gf_isom_close(file);
    remove(filename);
    
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

    LLVMFuzzerTestOneInput_56(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
