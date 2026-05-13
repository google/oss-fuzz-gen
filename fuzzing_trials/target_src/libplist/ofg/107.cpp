#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <plist/plist.h>

extern "C" int LLVMFuzzerTestOneInput_107(const uint8_t *data, size_t size) {
    // Ensure that the input data is not empty
    if (size == 0) return 0;

    // Allocate memory for the input string and ensure it's null-terminated
    char *input_str = (char *)malloc(size + 1);
    if (input_str == NULL) return 0;

    memcpy(input_str, data, size);
    input_str[size] = '\0'; // Null-terminate the string

    // Call the function-under-test
    plist_t plist = NULL;
    plist_from_xml(input_str, size, &plist);

    // Clean up
    free(input_str);
    if (plist != NULL) {
        plist_free(plist);
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

    LLVMFuzzerTestOneInput_107(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
