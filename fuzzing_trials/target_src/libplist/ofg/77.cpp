#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

extern "C" {
    #include "/src/libplist/libcnary/include/node.h"
    #include "/src/libplist/include/plist/plist.h"

    void plist_get_real_val(plist_t, double *);
}

extern "C" {

int LLVMFuzzerTestOneInput_77(const uint8_t *data, size_t size) {
    // Initialize plist_t and double variables
    plist_t plist;
    double real_val;

    // Ensure the data size is sufficient for initialization
    if (size < sizeof(plist_t)) {
        return 0;
    }

    // Initialize plist with some data from the input
    // Assuming plist_t is a pointer or a structure, adjust as necessary
    plist = (plist_t)data;

    // Call the function-under-test
    plist_get_real_val(plist, &real_val);

    // Optionally, print the real_val for debugging
    printf("Real value: %f\n", real_val);

    return 0;
}

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

    LLVMFuzzerTestOneInput_77(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
