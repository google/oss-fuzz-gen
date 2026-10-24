// This fuzz driver is generated for library kamailio, aiming to fuzz the following functions:
// parse_hname2 at parse_hname2.c:323:7 in parse_hname2.h
// get_hdr_field at msg_parser.c:74:7 in msg_parser.h
// parse_hname2_short at parse_hname2.c:333:7 in parse_hname2.h
// parse_sip_header_name at parse_hname2.c:239:7 in parse_hname2.h
// parse_to_body at parse_to.c:40:7 in parse_to.h
// parse_to at parse_to.c:67:7 in parse_to.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "parse_hname2.h"
#include "parse_to.h"
#include "msg_parser.h"

static char dummy_buffer[1024];

static void prepare_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file != NULL) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_59(const uint8_t *Data, size_t Size) {
    if (Size < 2) return 0;

    prepare_dummy_file(Data, Size);

    char *buffer = (char *)dummy_buffer;
    size_t copy_size = (Size < sizeof(dummy_buffer)) ? Size : sizeof(dummy_buffer) - 1;
    memcpy(buffer, Data, copy_size);
    buffer[copy_size] = '\0';

    char *begin = buffer;
    char *end = buffer + copy_size;

    hdr_field_t hdr;
    memset(&hdr, 0, sizeof(hdr_field_t));

    if (begin < end) {
        parse_hname2(begin, end, &hdr);
        get_hdr_field(begin, end, &hdr);
        parse_hname2_short(begin, end, &hdr);

        hdr_field_t hdr_field;
        memset(&hdr_field, 0, sizeof(hdr_field_t));
        parse_sip_header_name(begin, end, &hdr_field, 0, 0);

        to_body_t to_body;
        memset(&to_body, 0, sizeof(to_body_t));

        // Ensure the hdr structure is properly initialized before calling parse_to_body
        if (hdr.name.s != NULL && hdr.body.s != NULL) {
            parse_to_body(begin, end, &hdr);
        }

        // Ensure the buffer is not empty and to_body is initialized before calling parse_to
        if (begin < end && to_body.body.s != NULL) {
            parse_to(begin, end, &to_body);
        }
    }

    return 0;
}