#include <stdint.h>
#include <stdlib.h>
#include <string.h>  // Include for strdup
#include <gpac/isomedia.h>  // Include the GPAC library header for GF_ISOFile

int LLVMFuzzerTestOneInput_33(const uint8_t *data, size_t size) {
    GF_ISOFile *movie = NULL;

    // Ensure the data is null-terminated to be used as a string
    char *data_str = (char *)malloc(size + 1);
    if (data_str == NULL) {
        return 0;  // Return if memory allocation fails
    }
    memcpy(data_str, data, size);
    data_str[size] = '\0';  // Null-terminate the string

    // Open the ISO file using the null-terminated string
    movie = gf_isom_open(data_str, GF_ISOM_OPEN_READ, NULL);

    if (movie != NULL) {
        // Call the function-under-test
        gf_isom_close(movie);
    }

    free(data_str);  // Free the allocated memory for the string

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

    LLVMFuzzerTestOneInput_33(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
