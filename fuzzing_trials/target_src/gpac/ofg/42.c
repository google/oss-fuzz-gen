#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define GF_EXPORT

typedef uint32_t u32;

// Mock function to represent the function-under-test
GF_EXPORT void gf_isom_dump_supported_box_42(u32 idx, FILE *trace) {
    // Implementation of the function (not provided)
    fprintf(trace, "Dumping supported box with index: %u\n", idx);
}

int LLVMFuzzerTestOneInput_42(const uint8_t *data, size_t size) {
    // Ensure we have enough data to extract a u32 index
    if (size < sizeof(u32)) {
        return 0;
    }

    // Extract the index from the input data
    u32 idx = *((u32 *)data);

    // Open a temporary file to use as the trace file
    FILE *trace = tmpfile();
    if (trace == NULL) {
        return 0;
    }

    // Call the function-under-test
    gf_isom_dump_supported_box_42(idx, trace);

    // Close the temporary file
    fclose(trace);

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

    LLVMFuzzerTestOneInput_42(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
