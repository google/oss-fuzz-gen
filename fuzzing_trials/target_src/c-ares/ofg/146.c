#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>  // Include for memcpy
#include "ares.h"

int LLVMFuzzerTestOneInput_146(const uint8_t *data, size_t size) {
    if (size < sizeof(int)) {
        return 0;
    }

    /* Extract an integer code from the input data */
    int code;
    memcpy(&code, data, sizeof(int));

    /* Call the function-under-test */
    char *error_message = ares_strerror(code);

    /* Print the error message to ensure it is used */
    if (error_message != NULL) {
        printf("Error message: %s\n", error_message);
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

    LLVMFuzzerTestOneInput_146(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
