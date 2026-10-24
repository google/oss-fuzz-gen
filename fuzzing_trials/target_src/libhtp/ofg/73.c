#include <stdint.h>
#include <stdlib.h>
#include <sys/time.h>  // Include for struct timeval
#include <htp/htp.h>

int LLVMFuzzerTestOneInput_73(const uint8_t *data, size_t size) {
    // Initialize the connection parser object
    htp_connp_t *connp = htp_connp_create(NULL);
    if (connp == NULL) return 0;

    // Initialize the time object
    struct timeval time;  // Use struct timeval
    time.tv_sec = 0;      // Correct member name
    time.tv_usec = 0;     // Correct member name

    // Feed the input data to the connection parser
    if (size > 0) {
        htp_connp_req_data(connp, NULL, data, size);
    }

    // Call the function under test
    htp_connp_close(connp, &time);

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

    LLVMFuzzerTestOneInput_73(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
