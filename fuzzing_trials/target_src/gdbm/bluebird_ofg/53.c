#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>

// Define the slist structure
struct slist {
    int value;
    struct slist *next;
};

// Function-under-test
void slist_insert(struct slist **head, struct slist *new_node);

// Fuzzing harness
int LLVMFuzzerTestOneInput_53(const uint8_t *data, size_t size) {
    if (size < sizeof(int)) {
        return 0; // Not enough data to create a node
    }

    // Initialize the head of the list
    struct slist *head = NULL;

    // Create a new node from the input data
    struct slist *new_node = (struct slist *)malloc(sizeof(struct slist));
    if (new_node == NULL) {
        return 0; // Memory allocation failed
    }

    // Set the value of the new node
    memcpy(&new_node->value, data, sizeof(int));
    new_node->next = NULL;

    // Call the function-under-test
    slist_insert(&head, new_node);

    // Clean up
    struct slist *current = head;
    while (current != NULL) {
        struct slist *next = current->next;
        free(current);
        current = next;
    }

    return 0;
}