#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

// Assuming the function is defined in some library
extern char *htp_get_version();

int LLVMFuzzerTestOneInput_124(const uint8_t *data, size_t size) {
    // Call the function-under-test
    char *version = htp_get_version();

    // Print the version for debugging purposes
    if (version != NULL) {
        printf("HTP Version: %s\n", version);
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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_124(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
