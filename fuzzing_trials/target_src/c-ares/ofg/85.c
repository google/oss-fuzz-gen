#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_85(const uint8_t *data, size_t size) {
    /* Ensure the input data is sufficient to fill the ares_addr structure */
    if (size < sizeof(struct ares_addr)) {
        return 0;
    }

    struct ares_addr addr;
    /* Copy data into the struct ares_addr */
    memcpy(&addr, data, sizeof(struct ares_addr));

    /* Call the function-under-test */
    char *result = ares_dns_addr_to_ptr(&addr);

    /* Free the result if it's not NULL */
    if (result != NULL) {
        free(result);
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

    LLVMFuzzerTestOneInput_85(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
