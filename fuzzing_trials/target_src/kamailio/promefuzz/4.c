// This fuzz driver is generated for library kamailio, aiming to fuzz the following functions:
// parse_headers at msg_parser.c:307:5 in msg_parser.h
// parse_to_uri at parse_to.c:88:12 in parse_addr_spec.h
// parse_pai_header at parse_ppi_pai.c:132:5 in parse_ppi_pai.h
// parse_diversion_header at parse_diversion.c:185:5 in parse_diversion.h
// parse_privacy at parse_privacy.c:155:5 in parse_privacy.h
// parse_content_disposition at parse_disposition.c:378:5 in parse_disposition.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "parse_privacy.h"
#include "parse_diversion.h"
#include "parse_disposition.h"
#include "parse_ppi_pai.h"
#include "parse_addr_spec.h"
#include "msg_parser.h"  // Include the correct header for parse_headers

// A helper function to initialize a sip_msg structure
static void init_sip_msg(sip_msg_t *msg, const uint8_t *Data, size_t Size) {
    memset(msg, 0, sizeof(sip_msg_t));
    msg->buf = (char *)Data;
    msg->len = Size;
    msg->buf_size = Size;
    msg->headers = NULL;  // Ensure headers are initialized to NULL
}

// A helper function to write data to a dummy file
static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_4(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    sip_msg_t msg;
    init_sip_msg(&msg, Data, Size);

    // Write data to a dummy file if needed
    write_dummy_file(Data, Size);

    // Ensure headers are parsed before calling any header-specific functions
    if (parse_headers(&msg, 0, 0) == -1) {
        return 0;
    }

    // Fuzz parse_to_uri
    sip_uri_t *uri = parse_to_uri(&msg);
    if (uri != NULL) {
        // Do something with the parsed URI if needed
    }

    // Fuzz parse_pai_header
    int result_pai = parse_pai_header(&msg);
    if (result_pai == 0) {
        // Successfully parsed PAI header
    } else {
        // Handle parsing error or missing header
    }

    // Fuzz parse_diversion_header
    int result_diversion = parse_diversion_header(&msg);
    if (result_diversion == 0) {
        // Successfully parsed Diversion header
    } else {
        // Handle parsing error or missing header
    }

    // Fuzz parse_privacy
    int result_privacy = parse_privacy(&msg);
    if (result_privacy == 0) {
        // Successfully parsed Privacy header
    } else {
        // Handle parsing error or missing header
    }

    // Fuzz parse_content_disposition
    int result_content_disposition = parse_content_disposition(&msg);
    if (result_content_disposition == 0) {
        // Successfully parsed Content-Disposition header
    } else if (result_content_disposition == 1) {
        // Header not found
    } else {
        // Handle parsing error
    }

    return 0;
}