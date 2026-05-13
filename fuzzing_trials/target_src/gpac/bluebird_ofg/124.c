#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "/src/gpac/include/gpac/isomedia.h"

int LLVMFuzzerTestOneInput_124(const uint8_t *data, size_t size) {
    // Create a temporary file to store the input data
    char tmp_filename[] = "/tmp/fuzz_input_XXXXXX";
    int fd = mkstemp(tmp_filename);
    if (fd == -1) {
        return 0;
    }

    // Write the input data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        remove(tmp_filename);
        return 0;
    }
    close(fd);

    // Open the file using the gpac library
    GF_ISOFile *file = gf_isom_open(tmp_filename, GF_ISOM_OPEN_READ, NULL);
    if (file == NULL) {
        remove(tmp_filename);
        return 0;
    }

    // Try different values for root_meta and track_num
    Bool root_meta_options[] = {GF_FALSE, GF_TRUE};
    u32 track_num_options[] = {0, 1, 2, 3, 4};

    for (size_t i = 0; i < sizeof(root_meta_options) / sizeof(root_meta_options[0]); i++) {
        for (size_t j = 0; j < sizeof(track_num_options) / sizeof(track_num_options[0]); j++) {
            gf_isom_get_meta_item_count(file, root_meta_options[i], track_num_options[j]);
        }
    }

    gf_isom_close(file);

    // Clean up the temporary file
    remove(tmp_filename);
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

    LLVMFuzzerTestOneInput_124(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
