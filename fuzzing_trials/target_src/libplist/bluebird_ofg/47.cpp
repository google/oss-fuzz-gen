#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // Include this header for the 'close' function

extern "C" {
    #include "plist/plist.h"
}

extern "C" int LLVMFuzzerTestOneInput_47(const uint8_t *data, size_t size) {
    // Ensure that we have enough data to work with
    if (size < 4) {
        return 0;
    }

    // Initialize plist_t object
    plist_t plist = plist_new_dict();

    // Create a temporary file to write the plist data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        plist_free(plist);
        return 0;
    }
    FILE *file = fdopen(fd, "wb");
    if (!file) {
        close(fd);
        plist_free(plist);
        return 0;
    }

    // Extract values from the input data
    plist_format_t format = static_cast<plist_format_t>(data[0] % 3); // Assuming 3 possible formats
    plist_write_options_t options = static_cast<plist_write_options_t>(data[1] % 2); // Assuming 2 possible options

    // Call the function-under-test
    plist_write_to_stream(plist, file, format, options);

    // Clean up
    fclose(file);
    remove(tmpl);
    plist_free(plist);

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

    LLVMFuzzerTestOneInput_47(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
