#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <htslib/hts.h>
#include <htslib/sam.h> // Include the necessary library for bam_mods_queryi and hts_base_mod_state

int LLVMFuzzerTestOneInput_7(const uint8_t *data, size_t size) {
    // Ensure there is enough data to work with
    if (size < sizeof(int) * 2 + 1) {
        return 0;
    }

    // Initialize the parameters for bam_mods_queryi
    hts_base_mod_state *state = hts_base_mod_state_alloc();
    if (state == NULL) {
        return 0;
    }

    // Extract integer values from data
    int int_param1 = *((int *)data);
    int int_param2 = *((int *)(data + sizeof(int)));

    // Allocate memory for integer pointers
    int *int_ptr1 = (int *)malloc(sizeof(int));
    int *int_ptr2 = (int *)malloc(sizeof(int));

    if (int_ptr1 == NULL || int_ptr2 == NULL) {
        hts_base_mod_state_free(state);
        free(int_ptr1);
        free(int_ptr2);
        return 0;
    }

    // Initialize integer pointers with non-NULL values
    *int_ptr1 = 0;
    *int_ptr2 = 0;

    // Extract character value from data
    char char_param = *(data + sizeof(int) * 2);

    // Call the function-under-test
    int result = bam_mods_queryi(state, int_param1, int_ptr1, int_ptr2, &char_param);

    // Clean up
    hts_base_mod_state_free(state);
    free(int_ptr1);
    free(int_ptr2);

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

    LLVMFuzzerTestOneInput_7(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
