// This fuzz driver is generated for library kamailio, aiming to fuzz the following functions:
// parse_sip_msg_uri at parse_uri.c:1435:5 in parse_uri.h
// parse_pai_header at parse_ppi_pai.c:132:5 in parse_ppi_pai.h
// parse_diversion_header at parse_diversion.c:185:5 in parse_diversion.h
// parse_identityinfo_header at parse_identityinfo.c:325:5 in parse_identityinfo.h
// parse_privacy at parse_privacy.c:155:5 in parse_privacy.h
// free_pai_ppi_body at parse_ppi_pai.c:119:5 in parse_ppi_pai.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/time.h>
#include "parse_privacy.h"
#include "parse_diversion.h"
#include "parse_uri.h"
#include "parse_identityinfo.h"
#include "parse_ppi_pai.h"

#define DUMMY_FILE "./dummy_file"

static void initialize_sip_msg(struct sip_msg *msg) {
    memset(msg, 0, sizeof(struct sip_msg));
    msg->buf = (char *)malloc(1024);
    msg->len = 1024;
    msg->first_line.u.request.method.s = "INVITE";
    msg->first_line.u.request.method.len = 6;
    msg->first_line.u.request.uri.s = "sip:user@example.com";
    msg->first_line.u.request.uri.len = strlen(msg->first_line.u.request.uri.s);
    msg->first_line.u.request.version.s = "SIP/2.0";
    msg->first_line.u.request.version.len = 7;
}

static void cleanup_sip_msg(struct sip_msg *msg) {
    free(msg->buf);
}

static void fuzz_parse_sip_msg_uri(struct sip_msg *msg) {
    parse_sip_msg_uri(msg);
}

static void fuzz_parse_pai_header(struct sip_msg *msg) {
    parse_pai_header(msg);
}

static void fuzz_parse_diversion_header(struct sip_msg *msg) {
    parse_diversion_header(msg);
}

static void fuzz_parse_identityinfo_header(struct sip_msg *msg) {
    parse_identityinfo_header(msg);
}

static void fuzz_parse_privacy(struct sip_msg *msg) {
    parse_privacy(msg);
}

static void fuzz_free_pai_ppi_body(p_id_body_t *pid_b) {
    free_pai_ppi_body(pid_b);
}

int LLVMFuzzerTestOneInput_75(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(struct sip_msg)) {
        return 0;
    }

    struct sip_msg msg;
    initialize_sip_msg(&msg);

    // Write Data to a dummy file if needed by any function
    FILE *file = fopen(DUMMY_FILE, "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }

    // Fuzz different functions
    fuzz_parse_sip_msg_uri(&msg);
    fuzz_parse_pai_header(&msg);
    fuzz_parse_diversion_header(&msg);
    fuzz_parse_identityinfo_header(&msg);
    fuzz_parse_privacy(&msg);

    // Example usage of free_pai_ppi_body
    p_id_body_t pid_b;
    memset(&pid_b, 0, sizeof(pid_b));
    fuzz_free_pai_ppi_body(&pid_b);

    cleanup_sip_msg(&msg);
    return 0;
}