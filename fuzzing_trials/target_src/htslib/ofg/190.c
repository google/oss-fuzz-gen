#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <htslib/sam.h>  // Correct path for the declaration of bam_plp_init

// Define a dummy callback function that matches bam_plp_auto_f signature
static int dummy_callback_190(void *data) {
    // Do nothing, just return 0
    return 0;
}

int LLVMFuzzerTestOneInput_190(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for the void pointer
    if (size < sizeof(void *)) {
        return 0;
    }

    // Use the data as a void pointer
    void *user_data = (void *)data;

    // Call the function-under-test
    bam_plp_t plp = bam_plp_init(dummy_callback_190, user_data);

    // Normally, you would do something with `plp` here, like checking its state
    // or passing it to other functions, but for fuzzing, we just ensure it is called.

    // Clean up
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

    LLVMFuzzerTestOneInput_190(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
