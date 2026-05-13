// This fuzz driver is generated for library kamailio, aiming to fuzz the following functions:
// parse_disposition at parse_disposition.c:44:5 in parse_disposition.h
// print_disposition at parse_disposition.c:422:6 in parse_disposition.h
// free_disposition at parse_disposition.c:356:6 in parse_disposition.h
// parse_params at parse_param.c:561:5 in parse_param.h
// shm_free_params at parse_param.c:658:6 in parse_param.h
// find_not_quoted at parser_f.h:95:21 in parser_f.h
// free_disposition at parse_disposition.c:356:6 in parse_disposition.h
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "parse_disposition.h"
#include "parser_f.h"
#include "parse_param.h"

static void initialize_str(str *s, const char *data, size_t size) {
    s->s = (char *)malloc(size + 1);
    if (s->s != NULL) {
        memcpy(s->s, data, size);
        s->s[size] = '\0';
        s->len = size;
    } else {
        s->s = NULL;
        s->len = 0;
    }
}

static void cleanup_str(str *s) {
    if (s->s != NULL) {
        free(s->s);
        s->s = NULL;
    }
    s->len = 0;
}

int LLVMFuzzerTestOneInput_13(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Prepare a dummy file
    FILE *dummy_file = fopen("./dummy_file", "wb");
    if (dummy_file) {
        fwrite(Data, 1, Size, dummy_file);
        fclose(dummy_file);
    }

    // Initialize disposition structure
    struct disposition disp;
    memset(&disp, 0, sizeof(disp));

    // Initialize str structure
    str s;
    initialize_str(&s, (const char *)Data, Size);

    // Fuzz parse_disposition
    parse_disposition(&s, &disp);

    // Fuzz print_disposition
    print_disposition(&disp);

    // Fuzz free_disposition
    if (disp.params != NULL) {
        free_disposition(&disp.params);
    }

    // Initialize param hooks
    param_hooks_t hooks;
    memset(&hooks, 0, sizeof(hooks));

    // Initialize param_t pointer
    param_t *params = NULL;

    // Ensure string length is non-zero before parsing parameters
    if (s.len > 0) {
        // Fuzz parse_params
        parse_params(&s, CLASS_ANY, &hooks, &params);

        // Fuzz shm_free_params
        if (params != NULL) {
            shm_free_params(params);
        }
    }

    // Fuzz find_not_quoted
    if (Size > 0) {
        find_not_quoted(&s, Data[0]);
    }

    // Cleanup
    cleanup_str(&s);
    if (disp.params != NULL) {
        free_disposition(&disp.params);
    }

    return 0;
}