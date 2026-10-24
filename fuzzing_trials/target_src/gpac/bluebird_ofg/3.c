#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // Include this for mkstemp and unlink
#include "/src/gpac/include/gpac/isomedia.h"

#define MAX_SUPPORTED_INDEX 1000 // Define a reasonable maximum index value

int LLVMFuzzerTestOneInput_3(const uint8_t *data, size_t size) {
    // Ensure there is enough data to read a u32 index
    if (size < sizeof(u32)) {
        return 0;
    }

    // Read the index from the input data
    u32 idx = *(const u32 *)data;

    // Validate the index to ensure it is within a reasonable range
    // Assuming a hypothetical maximum index value, adjust as necessary
    if (idx > MAX_SUPPORTED_INDEX) {
        return 0;
    }

    // Create a temporary file to use as the trace
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    FILE *trace = fdopen(fd, "w+");
    if (!trace) {
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Call the function-under-test
    gf_isom_dump_supported_box(idx, trace);

    // Clean up
    fclose(trace);
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

    LLVMFuzzerTestOneInput_3(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
