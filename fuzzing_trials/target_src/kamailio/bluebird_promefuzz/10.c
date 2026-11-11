#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "/src/kamailio/src/core/parser/parse_from.h"
#include "/src/kamailio/src/core/parser/parse_addr_spec.h"
#include "/src/kamailio/src/core/parser/msg_parser.h"

#define DUMMY_FILE "./dummy_file"

static void initialize_sip_msg(sip_msg_t *msg, char *buf, unsigned int len) {
    memset(msg, 0, sizeof(sip_msg_t));
    msg->buf = buf;
    msg->len = len;
}

int LLVMFuzzerTestOneInput_10(const uint8_t *Data, size_t Size) {
    if (Size == 0) {
        return 0;
    }

    FILE *file = fopen(DUMMY_FILE, "wb");
    if (!file) {
        return 0;
    }
    fwrite(Data, 1, Size, file);
    fclose(file);

    char *buf = (char *)malloc(Size + 1);
    if (!buf) {
        return 0;
    }
    memcpy(buf, Data, Size);
    buf[Size] = '\0';

    sip_msg_t msg;
    initialize_sip_msg(&msg, buf, Size);

    if (parse_msg(buf, Size, &msg) == 0) {
        hdr_flags_t flags = 0; // Use appropriate flags as needed

        // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 1 of parse_headers
        parse_headers(&msg, REGISTER_LEN, 0);
        // End mutation: Producer.REPLACE_ARG_MUTATOR


        parse_from_header(&msg);
        parse_from_uri(&msg);
        parse_to_header(&msg);
    }

    free(buf);
    return 0;
}