// This fuzz driver is generated for library kamailio, aiming to fuzz the following functions:
// parse_rr_body at parse_rr.c:159:5 in parse_rr.h
// duplicate_rr at parse_rr.c:364:5 in parse_rr.h
// shm_duplicate_rr at parse_rr.c:373:5 in parse_rr.h
// print_rr at parse_rr.c:237:6 in parse_rr.h
// free_rr at parse_rr.c:217:6 in parse_rr.h
// free_rr at parse_rr.c:217:6 in parse_rr.h
// shm_free_rr at parse_rr.c:228:6 in parse_rr.h
// free_rr at parse_rr.c:217:6 in parse_rr.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "parse_rr.h"

#define DUMMY_FILE "./dummy_file"

static rr_t *create_dummy_rr() {
    rr_t *rr = (rr_t *)malloc(sizeof(rr_t));
    if (!rr) return NULL;
    
    rr->nameaddr.name.s = "dummy_name";
    rr->nameaddr.name.len = strlen("dummy_name");
    rr->nameaddr.uri.s = "sip:dummy@domain.com";
    rr->nameaddr.uri.len = strlen("sip:dummy@domain.com");
    rr->nameaddr.len = rr->nameaddr.name.len + rr->nameaddr.uri.len;
    
    rr->r2 = NULL;
    rr->params = NULL;
    rr->len = rr->nameaddr.len;
    rr->next = NULL;
    
    return rr;
}

int LLVMFuzzerTestOneInput_39(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0; // Not enough data to work with
    
    // Prepare a dummy rr_t structure
    rr_t *head = NULL;
    rr_t *new_rr = NULL;
    rr_t *shm_new_rr = NULL;
    
    // Fuzz parse_rr_body
    char *buf = (char *)malloc(Size + 1);
    if (buf) {
        memcpy(buf, Data, Size);
        buf[Size] = '\0';
        if (Size > 0 && buf[0] != '\0') { // Ensure buf is not empty and not a zero page
            parse_rr_body(buf, Size, &head);
        }
        free(buf);
    }
    
    // Fuzz duplicate_rr
    rr_t *dummy_rr = create_dummy_rr();
    if (dummy_rr) {
        duplicate_rr(&new_rr, dummy_rr);
    }
    
    // Fuzz shm_duplicate_rr
    if (dummy_rr) {
        shm_duplicate_rr(&shm_new_rr, dummy_rr);
    }
    
    // Fuzz print_rr
    FILE *dummy_file = fopen(DUMMY_FILE, "w");
    if (dummy_file) {
        if (dummy_rr) {
            print_rr(dummy_file, dummy_rr);
        }
        fclose(dummy_file);
    }
    
    // Cleanup
    free_rr(&head);
    if (new_rr) free_rr(&new_rr);
    if (shm_new_rr) shm_free_rr(&shm_new_rr);
    if (dummy_rr) free_rr(&dummy_rr);

    return 0;
}