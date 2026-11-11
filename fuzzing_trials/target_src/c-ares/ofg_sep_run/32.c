#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_32(const uint8_t *data, size_t size) {
    /* Ensure that the input size is sufficient for testing */
    if (size == 0) {
        return 0;
    }

    /* Initialize the output pointer */
    struct ares_txt_ext *txt_out = NULL;

    /* Call the function-under-test */
    int result = ares_parse_txt_reply_ext(data, (int)size, &txt_out);

    /* Free the allocated memory if the parsing was successful */
    if (result == ARES_SUCCESS && txt_out != NULL) {
        ares_free_data(txt_out);
    }

    return 0;
}