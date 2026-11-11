#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/kamailio/src/core/parser/msg_parser.h"
#include "/src/kamailio/src/core/parser/hf.h"

// Function-under-test
hdr_field_t *next_sibling_hdr_by_name(const hdr_field_t *hdr);

// Helper function to create a dummy hdr_field_t linked list
hdr_field_t *create_dummy_hdr_field_list() {
    hdr_field_t *head = (hdr_field_t *)malloc(sizeof(hdr_field_t));
    hdr_field_t *second = (hdr_field_t *)malloc(sizeof(hdr_field_t));
    hdr_field_t *third = (hdr_field_t *)malloc(sizeof(hdr_field_t));

    head->name.s = strdup("Header1");
    head->name.len = strlen("Header1");
    head->next = second;

    second->name.s = strdup("Header2");
    second->name.len = strlen("Header2");
    second->next = third;

    third->name.s = strdup("Header3");
    third->name.len = strlen("Header3");
    third->next = NULL;

    return head;
}

// Fuzzer entry point
int LLVMFuzzerTestOneInput_43(const uint8_t *data, size_t size) {
    // Create a dummy hdr_field_t list
    hdr_field_t *head = create_dummy_hdr_field_list();

    // Call the function-under-test
    hdr_field_t *result = next_sibling_hdr_by_name(head);

    // Clean up
    hdr_field_t *current = head;
    while (current != NULL) {
        hdr_field_t *next = current->next;
        free(current->name.s);
        free(current);
        current = next;
    }

    return 0;
}