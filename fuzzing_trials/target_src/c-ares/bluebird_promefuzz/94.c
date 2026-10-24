#include <stdint.h>
#include "stddef.h"
#include <string.h>
#include <stdlib.h>
#include "stdio.h"
#include "stdio.h"
#include <stdlib.h>
#include <string.h>
#include "ares.h"

static void fuzz_ares_parse_txt_reply_ext(const unsigned char *data, int size) {
    struct ares_txt_ext *txt_out = NULL;
    int result = ares_parse_txt_reply_ext(data, size, &txt_out);
    if (result == ARES_SUCCESS) {
        ares_free_data(txt_out);
    }
}

static void fuzz_ares_parse_aaaa_reply(const unsigned char *data, int size) {
    struct hostent *host = NULL;
    struct ares_addr6ttl addrttls[10];
    int naddrttls = 10;
    int result = ares_parse_aaaa_reply(data, size, &host, addrttls, &naddrttls);
    if (result == ARES_SUCCESS) {
        ares_free_hostent(host);
    }
}

static void fuzz_ares_parse_mx_reply(const unsigned char *data, int size) {
    struct ares_mx_reply *mx_out = NULL;
    int result = ares_parse_mx_reply(data, size, &mx_out);
    if (result == ARES_SUCCESS) {
        ares_free_data(mx_out);
    }
}

static void fuzz_ares_parse_srv_reply(const unsigned char *data, int size) {
    struct ares_srv_reply *srv_out = NULL;
    int result = ares_parse_srv_reply(data, size, &srv_out);
    if (result == ARES_SUCCESS) {
        ares_free_data(srv_out);
    }
}

static void fuzz_ares_parse_txt_reply(const unsigned char *data, int size) {
    struct ares_txt_reply *txt_out = NULL;
    int result = ares_parse_txt_reply(data, size, &txt_out);
    if (result == ARES_SUCCESS) {
        ares_free_data(txt_out);
    }
}

static void fuzz_ares_parse_uri_reply(const unsigned char *data, int size) {
    struct ares_uri_reply *uri_out = NULL;

    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 1 of ares_parse_uri_reply

    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 1 of ares_parse_uri_reply
    int result = ares_parse_uri_reply(data, -1, &uri_out);
    // End mutation: Producer.REPLACE_ARG_MUTATOR


    // End mutation: Producer.REPLACE_ARG_MUTATOR


    if (result == ARES_SUCCESS) {
        ares_free_data(uri_out);
    }
}

int LLVMFuzzerTestOneInput_94(const uint8_t *Data, size_t Size) {
    fuzz_ares_parse_txt_reply_ext(Data, Size);
    fuzz_ares_parse_aaaa_reply(Data, Size);
    fuzz_ares_parse_mx_reply(Data, Size);
    fuzz_ares_parse_srv_reply(Data, Size);
    fuzz_ares_parse_txt_reply(Data, Size);
    fuzz_ares_parse_uri_reply(Data, Size);
    return 0;
}