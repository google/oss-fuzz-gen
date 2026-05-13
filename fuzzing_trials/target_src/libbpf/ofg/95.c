#include <stdint.h>
#include <stdio.h>
#include <linux/types.h> // For __u32

// Assuming the function is defined in an external library
extern __u32 libbpf_minor_version();

int LLVMFuzzerTestOneInput_95(const uint8_t *data, size_t size) {
    // Call the function-under-test
    __u32 version = libbpf_minor_version();
    
    // Print the version to ensure the function is called
    printf("libbpf_minor_version: %u\n", version);

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

    LLVMFuzzerTestOneInput_95(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
