#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "sqlite3.h"

int LLVMFuzzerTestOneInput_407(const uint8_t *data, size_t size) {
    // Ensure the data is null-terminated to be used as a C string
    char *option = (char *)malloc(size + 1);
    if (option == NULL) {
        return 0;
    }
    memcpy(option, data, size);
    option[size] = '\0';

    // Call the function-under-test
    int result = sqlite3_compileoption_used(option);

    // Clean up
    free(option);

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

    LLVMFuzzerTestOneInput_407(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
