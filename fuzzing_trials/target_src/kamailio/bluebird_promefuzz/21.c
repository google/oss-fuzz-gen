#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include "/src/kamailio/src/core/parser/parse_uri.h"
#include "/src/kamailio/src/core/parser/parser_f.h"

#define MAX_BUFFER_SIZE 1024

static char *generate_string_from_data(const uint8_t *Data, size_t Size) {
    static char buffer[MAX_BUFFER_SIZE];
    size_t len = Size < MAX_BUFFER_SIZE - 1 ? Size : MAX_BUFFER_SIZE - 1;
    memcpy(buffer, Data, len);
    buffer[len] = '\0';
    return buffer;
}

int LLVMFuzzerTestOneInput_21(const uint8_t *Data, size_t Size) {
    if (Size < 2) return 0; // Ensure there's enough data for meaningful testing

    const char *p = generate_string_from_data(Data, Size);
    const char *pend = p + strlen(p);

    // Test eat_space_end
    char *result_eat_space_end = eat_space_end(p, pend);

    // Test is_empty_end
    int result_is_empty_end = is_empty_end(p, pend);

    // Test eat_lws_end
    char *result_eat_lws_end = eat_lws_end(p, pend);

    // Test eat_token_end
    char *result_eat_token_end = eat_token_end(p, pend);

    // Test eat_token2_end with a delimiter
    char delim = p[0]; // Use the first character as delimiter
    char *result_eat_token2_end = eat_token2_end(p, pend, delim);

    // Test normalize_tel_user
    str src;
    src.s = (char *)p;
    src.len = pend - p;
    char res[MAX_BUFFER_SIZE];
    int result_normalize_tel_user = normalize_tel_user(res, &src);

    return 0;
}