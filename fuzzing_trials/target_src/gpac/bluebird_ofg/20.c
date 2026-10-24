#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h> // Include for mkstemp, write, close, and unlink
#include "/src/gpac/include/gpac/isomedia.h"

int LLVMFuzzerTestOneInput_20(const uint8_t *data, size_t size) {
    GF_ISOFile *file = NULL;
    Bool root_meta = 1; // Initialize to a valid boolean value
    u32 track_num = 1;  // Initialize to a valid track number

    // Create a temporary file to simulate an ISO file
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0; // If file creation fails, exit early
    }

    // Write the fuzz data to the temporary file
    write(fd, data, size);
    close(fd);

    // Open the ISO file with the temporary file path
    file = gf_isom_open(tmpl, GF_ISOM_OPEN_READ, NULL);
    if (file != NULL) {
        // Call the function-under-test
        gf_isom_remove_meta_xml(file, root_meta, track_num);

        // Close the ISO file
        gf_isom_close(file);
    }

    // Remove the temporary file
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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_20(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
