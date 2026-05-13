#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <htp/htp.h>

// Function to create and initialize an htp_connp_t
htp_connp_t *create_connp() {
    // Initialize a new connection parser
    htp_connp_t *connp = htp_connp_create(NULL);
    if (connp == NULL) {
        return NULL; // Exit if memory allocation fails
    }
    return connp;
}

int LLVMFuzzerTestOneInput_87(const uint8_t *data, size_t size) {
    // Create and initialize htp_connp_t
    htp_connp_t *connp = create_connp();
    if (connp == NULL) {
        return 0; // Exit if memory allocation fails
    }

    // Initialize htp_tx_t with the connection parser
    htp_tx_t *tx = htp_tx_create(connp);
    if (tx == NULL) {
        htp_connp_destroy_all(connp);
        return 0; // Exit if memory allocation fails
    }

    // Ensure that user_data is not NULL and is meaningful
    if (size > 0) {
        // Copy the input data to a new buffer to ensure it's null-terminated
        char *user_data = (char *)malloc(size + 1);
        if (user_data == NULL) {
            htp_tx_destroy(tx);
            htp_connp_destroy_all(connp);
            return 0; // Exit if memory allocation fails
        }
        memcpy(user_data, data, size);
        user_data[size] = '\0'; // Null-terminate the string

        // Call the function-under-test
        htp_tx_set_user_data(tx, user_data);

        // Free the allocated user_data
        free(user_data);
    }

    // Clean up
    htp_tx_destroy(tx);
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

    LLVMFuzzerTestOneInput_87(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
