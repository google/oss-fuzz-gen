#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "/src/libhtp/htp/htp.h" // Correct path for htp.h

int LLVMFuzzerTestOneInput_86(const uint8_t *data, size_t size) {
    htp_tx_t *tx = (htp_tx_t *)malloc(sizeof(htp_tx_t));
    if (tx == NULL) {
        return 0; // Exit if memory allocation fails
    }

    // Ensure data is not NULL and size is greater than 0
    if (data != NULL && size > 0) {
        // Use the data as a pointer to user data
        void *user_data = (void *)data;

        // Call the function-under-test
        htp_tx_set_user_data(tx, user_data);
    }

    // Clean up
    free(tx);

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

    LLVMFuzzerTestOneInput_86(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
