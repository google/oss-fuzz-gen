// This fuzz driver is generated for library cares, aiming to fuzz the following functions:
// ares_dns_rr_set_u16 at ares_dns_record.c:1158:15 in ares_dns_record.h
// ares_dns_record_destroy at ares_dns_record.c:223:6 in ares_dns_record.h
// ares_dns_record_destroy at ares_dns_record.c:223:6 in ares_dns_record.h
// ares_dns_rr_set_opt at ares_dns_record.c:1404:15 in ares_dns_record.h
// ares_dns_record_destroy at ares_dns_record.c:223:6 in ares_dns_record.h
// ares_search_dnsrec at ares_search.c:473:15 in ares.h
// ares_dns_record_destroy at ares_dns_record.c:223:6 in ares_dns_record.h
// ares_dns_record_create at ares_dns_record.c:52:15 in ares_dns_record.h
// ares_dns_record_query_add at ares_dns_record.c:252:15 in ares_dns_record.h
// ares_dns_record_destroy at ares_dns_record.c:223:6 in ares_dns_record.h
// ares_dns_record_destroy at ares_dns_record.c:223:6 in ares_dns_record.h
// ares_dns_record_rr_add at ares_dns_record.c:396:15 in ares_dns_record.h
// ares_dns_record_destroy at ares_dns_record.c:223:6 in ares_dns_record.h
// ares_dns_record_destroy at ares_dns_record.c:223:6 in ares_dns_record.h
// ares_dns_rr_set_u8 at ares_dns_record.c:1140:15 in ares_dns_record.h
// ares_dns_record_destroy at ares_dns_record.c:223:6 in ares_dns_record.h
// ares_dns_rr_set_u16 at ares_dns_record.c:1158:15 in ares_dns_record.h
// ares_dns_record_destroy at ares_dns_record.c:223:6 in ares_dns_record.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ares.h>
#include <ares_dns_record.h>

static void dummy_callback(void *arg, int status, int timeouts, unsigned char *abuf, int alen) {
    // Dummy callback function for ares_search_dnsrec
}

int LLVMFuzzerTestOneInput_35(const uint8_t *Data, size_t Size) {
    // Check if the input size is sufficient to avoid buffer overflows
    if (Size < sizeof(unsigned short) * 5 + 1) {
        return 0;  // Not enough data
    }

    ares_dns_record_t *dnsrec = NULL;
    ares_dns_rr_t *rr = NULL;
    ares_channel_t *channel = NULL;
    
    unsigned short id = *(unsigned short *)Data;
    unsigned short flags = *(unsigned short *)(Data + 2);
    ares_dns_opcode_t opcode = *(ares_dns_opcode_t *)(Data + 4);
    ares_dns_rcode_t rcode = *(ares_dns_rcode_t *)(Data + 6);

    const char *hostname = (const char *)(Data + 8);
    size_t hostname_len = strnlen(hostname, Size - 8);
    if (8 + hostname_len + 1 >= Size) {
        return 0;  // Avoid reading beyond buffer
    }

    size_t offset = 8 + hostname_len + 1;
    if (offset + sizeof(ares_dns_rec_type_t) + sizeof(ares_dns_class_t) >= Size) {
        return 0;  // Avoid reading beyond buffer
    }

    ares_dns_rec_type_t qtype = *(ares_dns_rec_type_t *)(Data + offset);
    offset += sizeof(ares_dns_rec_type_t);

    ares_dns_class_t qclass = *(ares_dns_class_t *)(Data + offset);
    offset += sizeof(ares_dns_class_t);

    if (ares_dns_record_create(&dnsrec, id, flags, opcode, rcode) != ARES_SUCCESS) {
        return 0;
    }

    if (ares_dns_record_query_add(dnsrec, hostname, qtype, qclass) != ARES_SUCCESS) {
        ares_dns_record_destroy(dnsrec);
        return 0;
    }

    const char *rr_name = (const char *)(Data + offset);
    size_t rr_name_len = strnlen(rr_name, Size - offset);
    offset += rr_name_len + 1;
    if (offset + sizeof(ares_dns_rec_type_t) + sizeof(ares_dns_class_t) + sizeof(unsigned int) >= Size) {
        ares_dns_record_destroy(dnsrec);
        return 0;  // Avoid reading beyond buffer
    }

    ares_dns_rec_type_t rr_type = *(ares_dns_rec_type_t *)(Data + offset);
    offset += sizeof(ares_dns_rec_type_t);

    ares_dns_class_t rr_class = *(ares_dns_class_t *)(Data + offset);
    offset += sizeof(ares_dns_class_t);

    unsigned int ttl = *(unsigned int *)(Data + offset);
    offset += sizeof(unsigned int);

    if (ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ANSWER, rr_name, rr_type, rr_class, ttl) != ARES_SUCCESS) {
        ares_dns_record_destroy(dnsrec);
        return 0;
    }

    if (offset + sizeof(unsigned char) + sizeof(unsigned short) * 2 >= Size) {
        ares_dns_record_destroy(dnsrec);
        return 0;  // Avoid reading beyond buffer
    }

    unsigned char u8_val = *(Data + offset);
    offset += sizeof(unsigned char);

    if (ares_dns_rr_set_u8(rr, 0, u8_val) != ARES_SUCCESS) {
        ares_dns_record_destroy(dnsrec);
        return 0;
    }

    unsigned short u16_val1 = *(unsigned short *)(Data + offset);
    offset += sizeof(unsigned short);

    if (ares_dns_rr_set_u16(rr, 0, u16_val1) != ARES_SUCCESS) {
        ares_dns_record_destroy(dnsrec);
        return 0;
    }

    unsigned short u16_val2 = *(unsigned short *)(Data + offset);
    offset += sizeof(unsigned short);

    if (ares_dns_rr_set_u16(rr, 0, u16_val2) != ARES_SUCCESS) {
        ares_dns_record_destroy(dnsrec);
        return 0;
    }

    if (offset + sizeof(unsigned short) >= Size) {
        ares_dns_record_destroy(dnsrec);
        return 0;  // Avoid reading beyond buffer
    }

    unsigned short opt = *(unsigned short *)(Data + offset);
    offset += sizeof(unsigned short);

    const unsigned char *val = Data + offset;
    size_t val_len = Size - offset;

    if (ares_dns_rr_set_opt(rr, 0, opt, val, val_len) != ARES_SUCCESS) {
        ares_dns_record_destroy(dnsrec);
        return 0;
    }

    ares_search_dnsrec(channel, dnsrec, dummy_callback, NULL);

    ares_dns_record_destroy(dnsrec);
    return 0;
}