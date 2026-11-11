#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "/src/hoextdown/src/html.h"  // Correct path to the header file

// Remove extern "C" as this is a C file, not C++
int LLVMFuzzerTestOneInput_45(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to create a non-null string for tagname
    if (size < 1) {
        return 0;
    }

    // Use the first byte of data to determine the length of the tagname
    size_t tagname_length = data[0] % (size - 1) + 1;  // Ensure tagname_length is at least 1

    // Allocate memory for tagname and ensure it's null-terminated
    char tagname[tagname_length + 1];
    memcpy(tagname, data + 1, tagname_length);
    tagname[tagname_length] = '\0';

    // Call the function-under-test
    hoedown_html_tag result = hoedown_html_is_tag(data, size, tagname);

    // Use the result in some way to prevent the compiler from optimizing it away
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

    LLVMFuzzerTestOneInput_45(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
