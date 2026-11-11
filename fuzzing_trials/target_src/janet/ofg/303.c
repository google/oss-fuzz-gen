#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Assuming JanetEVGenericMessage is a struct, define it here for the purpose of this harness
typedef struct {
    int message_type;
    void *data;
    size_t data_length;
} JanetEVGenericMessage;

// Function-under-test
void janet_ev_default_threaded_callback(JanetEVGenericMessage msg);

int LLVMFuzzerTestOneInput_303(const uint8_t *data, size_t size) {
    if (size < sizeof(int) + sizeof(size_t)) {
        return 0;
    }

    // Initialize a JanetEVGenericMessage
    JanetEVGenericMessage msg;

    // Set the message_type to the first 4 bytes of data
    memcpy(&msg.message_type, data, sizeof(int));

    // Set the data_length to the next 8 bytes of data
    memcpy(&msg.data_length, data + sizeof(int), sizeof(size_t));

    // Ensure data_length does not exceed the remaining size
    if (msg.data_length > size - sizeof(int) - sizeof(size_t)) {
        msg.data_length = size - sizeof(int) - sizeof(size_t);
    }

    // Set the data pointer to the remaining bytes
    msg.data = (void *)(data + sizeof(int) + sizeof(size_t));

    // Call the function-under-test
    janet_ev_default_threaded_callback(msg);

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

    LLVMFuzzerTestOneInput_303(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
