#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>

// Define the slist structure
struct slist {
    struct slist *next;
    void *data;
};

// Function prototype for the function-under-test
void slist_free(struct slist *list);

// Helper function to create a slist from fuzzer input data
struct slist *create_slist_from_data(const uint8_t *data, size_t size) {
    if (size == 0) return NULL;

    struct slist *head = (struct slist *)malloc(sizeof(struct slist));
    if (!head) return NULL;

    head->data = malloc(size); // Allocate data based on input size
    if (!head->data) {
        free(head);
        return NULL;
    }
    memcpy(head->data, data, size);

    head->next = NULL;
    return head;
}

int LLVMFuzzerTestOneInput_39(const uint8_t *data, size_t size) {
    // Create a slist from fuzzer input data
    struct slist *test_list = create_slist_from_data(data, size);
    if (!test_list) return 0;

    // Call the function-under-test
    slist_free(test_list);

    return 0;
}