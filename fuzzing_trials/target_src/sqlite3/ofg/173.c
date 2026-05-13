#include <stdint.h>
#include <stddef.h>
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_173(const uint8_t *data, size_t size) {
    int errCode;
    const char *msg;
    void *pArg = (void *)0x1; // Non-NULL value

    if (size < sizeof(int) + 1) {
        return 0; // Not enough data to extract int and non-empty string
    }

    // Extract an integer from the data
    errCode = *((int *)data);

    // Ensure the message is a null-terminated string
    msg = (const char *)(data + sizeof(int));
    if (msg[size - sizeof(int) - 1] != '\0') {
        return 0; // Ensure null-termination
    }

    // Call the function-under-test
    sqlite3_log(errCode, msg, pArg);

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

    LLVMFuzzerTestOneInput_173(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
