#include <linux/bpf.h>
#include "/src/libbpf/src/libbpf.h"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput_135(const uint8_t *data, size_t size) {
    struct bpf_object *obj;
    __u32 kversion;

    // Ensure the size is enough to extract a __u32 value
    if (size < sizeof(__u32)) {
        return 0;
    }

    // Initialize the bpf_object
    obj = bpf_object__open("dummy_path");  // Use a dummy path for initialization
    if (!obj) {
        return 0;
    }

    // Extract a __u32 value from the input data
    kversion = *((__u32 *)data);

    // Call the function-under-test
    bpf_object__set_kversion(obj, kversion);

    // Clean up
    bpf_object__close(obj);

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

    LLVMFuzzerTestOneInput_135(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
