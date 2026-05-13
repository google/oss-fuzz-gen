#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <htp/htp.h>

int LLVMFuzzerTestOneInput_148(const uint8_t *data, size_t size) {
    // Declare and initialize the necessary variables
    htp_connp_t *connp = htp_connp_create(NULL);
    htp_time_t current_time = {0, 0}; // Initialize with zero values

    // Ensure connp is not NULL
    if (connp == NULL) {
        return 0;
    }

    // Call the function-under-test
    int result = htp_connp_req_data(connp, &current_time, data, size);

    // Clean up
    htp_connp_destroy_all(connp);

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

    LLVMFuzzerTestOneInput_148(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
