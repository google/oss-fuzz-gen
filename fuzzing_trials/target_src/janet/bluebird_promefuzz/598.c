#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static void prepare_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

static Janet create_valid_janet(const uint8_t *Data, size_t Size) {
    Janet janet_obj;
    if (Size >= sizeof(Janet)) {
        memcpy(&janet_obj, Data, sizeof(Janet));
    } else {
        janet_obj.u64 = 0; // Default to a safe value
    }
    return janet_obj;
}

int LLVMFuzzerTestOneInput_598(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet)) {
        return 0; // Not enough data to form a Janet object
    }

    // Prepare dummy file if needed
    prepare_dummy_file(Data, Size);

    // Initialize a valid Janet object from input data
    Janet janet_obj = create_valid_janet(Data, Size);

    // Fuzz janet_gcunlock
    int handle = Data[0] % 2; // Use first byte to decide handle
    janet_gcunlock(handle);

    // Fuzz janet_gcunroot
    int unroot_result = janet_gcunroot(janet_obj);
    (void)unroot_result; // Silence unused variable warning

    // Fuzz janet_mark
    janet_mark(janet_obj);

    // Fuzz janet_gcunrootall
    int unrootall_result = janet_gcunrootall(janet_obj);
    (void)unrootall_result; // Silence unused variable warning

    // Fuzz janet_deinit
    janet_deinit();

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

    LLVMFuzzerTestOneInput_598(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
