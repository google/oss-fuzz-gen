#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

// Mock function definition for dwarf_get_LNS_name_245
// In a real-world scenario, this would be included from the appropriate library header.
int dwarf_get_LNS_name_245(unsigned int lns, const char **name) {
    // Mock behavior: Assign a static name based on the input for demonstration purposes.
    static const char *names[] = {"LNS_copy", "LNS_advance_pc", "LNS_advance_line"};
    if (lns < sizeof(names) / sizeof(names[0])) {
        *name = names[lns];
        return 0; // Success
    }
    *name = "Unknown";
    return -1; // Failure
}

int LLVMFuzzerTestOneInput_245(const uint8_t *data, size_t size) {
    if (size < sizeof(unsigned int)) {
        return 0; // Not enough data to form an unsigned int
    }

    unsigned int lns = *(unsigned int *)data;
    const char *name = NULL;

    // Call the function-under-test
    int result = dwarf_get_LNS_name_245(lns, &name);

    // Optionally, print the result for debugging purposes
    if (result == 0) {
        printf("LNS: %u, Name: %s\n", lns, name);
    } else {
        printf("LNS: %u, Name: Unknown\n", lns);
    }

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

    LLVMFuzzerTestOneInput_245(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
