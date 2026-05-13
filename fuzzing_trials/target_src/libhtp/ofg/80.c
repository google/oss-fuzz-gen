#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/libhtp/htp/htp.h" // Correct path to the header file
#include "/src/libhtp/htp/htp_connection_parser.h" // Include the header where htp_connp_t is fully defined
#include "/src/libhtp/htp/htp_transaction.h" // Include the header where htp_time_t is fully defined

int LLVMFuzzerTestOneInput_80(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    htp_connp_t *connp = htp_connp_create(NULL); // Use the library function to create an instance
    htp_time_t time; // Declare htp_time_t as a variable, not a pointer
    const void *input_data = (const void *)data;
    size_t input_size = size;

    // Ensure that connp is not NULL
    if (connp == NULL) {
        return 0;
    }

    // Initialize htp_time_t structure
    memset(&time, 0, sizeof(htp_time_t));

    // Call the function-under-test
    int result = htp_connp_res_data(connp, &time, input_data, input_size);

    // Clean up
    htp_connp_destroy_all(connp); // Use the appropriate library function to free resources

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

    LLVMFuzzerTestOneInput_80(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
