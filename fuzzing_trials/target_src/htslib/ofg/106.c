#include <stdint.h>
#include <stdlib.h>
#include <htslib/sam.h>

int LLVMFuzzerTestOneInput_106(const uint8_t *data, size_t size) {
    // Initialize the bam_plp_t variable
    bam_plp_t plp = bam_plp_init(NULL, NULL);

    // Ensure that the bam_plp_t is not NULL
    if (plp == NULL) {
        return 0;
    }

    // Call the function-under-test
    bam_plp_destroy(plp);

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

    LLVMFuzzerTestOneInput_106(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
