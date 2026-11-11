#include <sys/stat.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "libbpf.h"

#ifdef __cplusplus
extern "C" {
#endif

extern int LLVMFuzzerTestOneInput_57(const uint8_t *data, size_t size) {
    // Ensure that we have enough data to initialize the structure
    if (size < sizeof(struct bpf_object_skeleton)) {
        return 0;
    }

    // Allocate memory for the bpf_object_skeleton structure
    struct bpf_object_skeleton *skeleton = (struct bpf_object_skeleton *)malloc(sizeof(struct bpf_object_skeleton));
    if (!skeleton) {
        return 0; // Handle memory allocation failure
    }

    // Initialize the skeleton structure to zero
    memset(skeleton, 0, sizeof(struct bpf_object_skeleton));

    // Copy data into the allocated structure
    memcpy(skeleton, data, sizeof(struct bpf_object_skeleton));

    // Ensure that the skeleton is properly initialized before use
    if (skeleton->name == NULL || skeleton->progs == NULL || skeleton->maps == NULL) {
        free(skeleton);
        return 0;
    }

    // Call the function-under-test
    bpf_object__detach_skeleton(skeleton);

    // Free the allocated memory
    free(skeleton);

    return 0;
}

#ifdef __cplusplus
}
#endif
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

    LLVMFuzzerTestOneInput_57(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
