#include <stdint.h>
#include <stdlib.h>
#include <linux/bpf.h>
#include <linux/types.h>  // Include for __u32

// Dummy struct definition for bpf_map to allow compilation
struct bpf_map {
    int dummy;  // Placeholder member
};

// Function prototype
__u32 bpf_map__btf_key_type_id(const struct bpf_map *map);

int LLVMFuzzerTestOneInput_97(const uint8_t *data, size_t size) {
    // Ensure size is sufficient to create a bpf_map
    if (size < sizeof(struct bpf_map)) {
        return 0;
    }

    // Cast data to a bpf_map pointer
    const struct bpf_map *map = (const struct bpf_map *)data;

    // Call the function under test
    __u32 result = bpf_map__btf_key_type_id(map);

    // Use the result to prevent it from being optimized away
    (void)result;

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

    LLVMFuzzerTestOneInput_97(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
