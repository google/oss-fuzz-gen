// This fuzz driver is generated for library cares, aiming to fuzz the following functions:
// ares_free_data at ares_data.c:46:6 in ares.h
// ares_free_data at ares_data.c:46:6 in ares.h
// ares_free_data at ares_data.c:46:6 in ares.h
// ares_free_data at ares_data.c:46:6 in ares.h
// ares_free_data at ares_data.c:46:6 in ares.h
// ares_parse_txt_reply at ares_parse_txt_reply.c:126:5 in ares.h
// ares_parse_txt_reply_ext at ares_parse_txt_reply.c:136:5 in ares.h
// ares_parse_mx_reply at ares_parse_mx_reply.c:30:5 in ares.h
// ares_parse_uri_reply at ares_parse_uri_reply.c:30:5 in ares.h
// ares_parse_aaaa_reply at ares_parse_aaaa_reply.c:51:5 in ares.h
// ares_free_hostent at ares_free_hostent.c:33:6 in ares.h
// ares_parse_srv_reply at ares_parse_srv_reply.c:30:5 in ares.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ares.h>

static void free_txt_reply(struct ares_txt_reply *txt) {
    struct ares_txt_reply *next;
    while (txt) {
        next = txt->next;
        ares_free_data(txt);
        txt = next;
    }
}

static void free_txt_ext(struct ares_txt_ext *txt) {
    struct ares_txt_ext *next;
    while (txt) {
        next = txt->next;
        ares_free_data(txt);
        txt = next;
    }
}

static void free_mx_reply(struct ares_mx_reply *mx) {
    struct ares_mx_reply *next;
    while (mx) {
        next = mx->next;
        ares_free_data(mx);
        mx = next;
    }
}

static void free_uri_reply(struct ares_uri_reply *uri) {
    struct ares_uri_reply *next;
    while (uri) {
        next = uri->next;
        ares_free_data(uri);
        uri = next;
    }
}

static void free_srv_reply(struct ares_srv_reply *srv) {
    struct ares_srv_reply *next;
    while (srv) {
        next = srv->next;
        ares_free_data(srv);
        srv = next;
    }
}

int LLVMFuzzerTestOneInput_34(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    struct ares_txt_reply *txt_out = NULL;
    struct ares_txt_ext *txt_ext_out = NULL;
    struct ares_mx_reply *mx_out = NULL;
    struct ares_uri_reply *uri_out = NULL;
    struct hostent *host = NULL;
    struct ares_srv_reply *srv_out = NULL;
    struct ares_addr6ttl addrttls[10];
    int naddrttls = 10;

    // Fuzz ares_parse_txt_reply
    ares_parse_txt_reply(Data, Size, &txt_out);
    free_txt_reply(txt_out);

    // Fuzz ares_parse_txt_reply_ext
    ares_parse_txt_reply_ext(Data, Size, &txt_ext_out);
    free_txt_ext(txt_ext_out);

    // Fuzz ares_parse_mx_reply
    ares_parse_mx_reply(Data, Size, &mx_out);
    free_mx_reply(mx_out);

    // Fuzz ares_parse_uri_reply
    ares_parse_uri_reply(Data, Size, &uri_out);
    free_uri_reply(uri_out);

    // Fuzz ares_parse_aaaa_reply
    ares_parse_aaaa_reply(Data, Size, &host, addrttls, &naddrttls);
    if (host) ares_free_hostent(host);

    // Fuzz ares_parse_srv_reply
    ares_parse_srv_reply(Data, Size, &srv_out);
    free_srv_reply(srv_out);

    return 0;
}