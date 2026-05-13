#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>
#include <unistd.h>
#include <fcntl.h> // Include this header for mkstemp

int LLVMFuzzerTestOneInput_134(const uint8_t *data, size_t size) {
    // File name and file access template
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0; // Unable to create temporary file
    }
    close(fd);

    const char *file_name = tmpl;

    // Ensure size is large enough to extract necessary data
    if (size < 2 * sizeof(unsigned int) + 3 * sizeof(hid_t)) {
        unlink(tmpl);
        return 0;
    }

    // Extracting unsigned int and hid_t values from data
    unsigned int flags = *((unsigned int *)data);
    data += sizeof(unsigned int);
    size -= sizeof(unsigned int);

    unsigned int create_mode = *((unsigned int *)data);
    data += sizeof(unsigned int);
    size -= sizeof(unsigned int);

    hid_t fcpl_id = *((hid_t *)data);
    data += sizeof(hid_t);
    size -= sizeof(hid_t);

    hid_t fapl_id = *((hid_t *)data);
    data += sizeof(hid_t);
    size -= sizeof(hid_t);

    hid_t es_id = *((hid_t *)data);
    data += sizeof(hid_t);
    size -= sizeof(hid_t);

    // Call the function-under-test
    hid_t file_id = H5Fcreate_async(file_name, flags, fcpl_id, fapl_id, es_id);

    // Clean up
    if (file_id >= 0) {
        H5Fclose(file_id);
    }
    unlink(tmpl);

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

    LLVMFuzzerTestOneInput_134(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
