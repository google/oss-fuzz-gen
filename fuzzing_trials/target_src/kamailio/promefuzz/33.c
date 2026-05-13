// This fuzz driver is generated for library kamailio, aiming to fuzz the following functions:
// parse_via_header at parse_via.c:2794:5 in parse_via.h
// parse_require at parse_require.c:35:5 in parse_require.h
// get_src_uri at msg_parser.c:1186:5 in msg_parser.h
// parse_nameaddr at parse_nameaddr.c:41:5 in parse_nameaddr.h
// parse_route_headers at parse_rr.c:538:5 in parse_rr.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "parse_nameaddr.h"
#include "parse_option_tags.h"
#include "parse_via.h"
#include "parse_require.h"
#include "parse_rr.h"
#include "msg_parser.h"

static void fuzz_parse_via_header(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(struct sip_msg) + sizeof(int) + sizeof(struct via_body *)) return;

    struct sip_msg *msg = (struct sip_msg *)Data;
    int index = *(int *)(Data + sizeof(struct sip_msg));
    struct via_body *via = NULL;

    parse_via_header(msg, index, &via);
}

static void fuzz_parse_require(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(struct sip_msg)) return;

    struct sip_msg *msg = (struct sip_msg *)Data;

    parse_require(msg);
}

static void fuzz_get_src_uri(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(sip_msg_t) + sizeof(int) + sizeof(str)) return;

    sip_msg_t *msg = (sip_msg_t *)Data;
    int tmode = *(int *)(Data + sizeof(sip_msg_t));
    str uri;
    uri.s = (char *)(Data + sizeof(sip_msg_t) + sizeof(int));
    uri.len = Size - sizeof(sip_msg_t) - sizeof(int);

    get_src_uri(msg, tmode, &uri);
}

static void fuzz_parse_nameaddr(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(str) + sizeof(name_addr_t)) return;

    str s;
    s.s = (char *)Data;
    s.len = Size;

    name_addr_t na;
    parse_nameaddr(&s, &na);
}

static void fuzz_parse_route_headers(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(sip_msg_t)) return;

    sip_msg_t *msg = (sip_msg_t *)Data;

    parse_route_headers(msg);
}

int LLVMFuzzerTestOneInput_33(const uint8_t *Data, size_t Size) {
    fuzz_parse_via_header(Data, Size);
    fuzz_parse_require(Data, Size);
    fuzz_get_src_uri(Data, Size);
    fuzz_parse_nameaddr(Data, Size);
    fuzz_parse_route_headers(Data, Size);
    
    return 0;
}