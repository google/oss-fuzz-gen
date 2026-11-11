#include <stdint.h>
#include <stdlib.h>
#include <plist/plist.h>

extern "C" {
    // Function signature from the project
    int plist_date_val_compare(plist_t plist, int32_t date1, int32_t date2);
}

extern "C" int LLVMFuzzerTestOneInput_89(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for at least two int32_t values
    if (size < 2 * sizeof(int32_t)) {
        return 0;
    }

    // Initialize a plist node
    plist_t plist = plist_new_dict();

    // Extract two int32_t values from the input data
    int32_t date1 = *(reinterpret_cast<const int32_t*>(data));
    int32_t date2 = *(reinterpret_cast<const int32_t*>(data + sizeof(int32_t)));

    // Call the function-under-test
    int result = plist_date_val_compare(plist, date1, date2);

    // Clean up plist
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

    LLVMFuzzerTestOneInput_89(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
