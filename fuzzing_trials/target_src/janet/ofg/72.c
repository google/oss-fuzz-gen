#include <stdint.h>
#include <stddef.h>
#include <janet.h>

extern int32_t janet_gethalfrange(const Janet *, int32_t, int32_t, const char *);

int LLVMFuzzerTestOneInput_72(const uint8_t *data, size_t size) {
    if (size < sizeof(Janet) + sizeof(int32_t) * 2 + sizeof(char)) {
        return 0; // Not enough data to form valid inputs
    }

    // Initialize the Janet array
    Janet janetArray[1];
    janetArray[0] = janet_wrap_integer((int32_t)data[0]);

    // Extract int32_t parameters
    int32_t start = (int32_t)data[1];
    int32_t end = (int32_t)data[2];

    // Extract a character for the string
    char str[2] = {(char)data[3], '\0'};

    // Call the function-under-test
    int32_t result = janet_gethalfrange(janetArray, start, end, str);

    // Use the result in some way to avoid compiler optimizing it out
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_72(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
