#include <stdint.h>
#include <stdlib.h>
#include <plist/plist.h>

extern "C" {
    int plist_uint_val_compare(plist_t, uint64_t);
}

extern "C" int LLVMFuzzerTestOneInput_96(const uint8_t *data, size_t size) {
    if (size < sizeof(uint64_t)) {
        return 0;
    }

    plist_t plistNode = plist_new_uint(*(uint64_t*)data);
    uint64_t value = *(uint64_t*)(data + sizeof(uint64_t));

    plist_uint_val_compare(plistNode, value);

    plist_free(plistNode);

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

    LLVMFuzzerTestOneInput_96(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
