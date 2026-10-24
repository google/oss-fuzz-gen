#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "/src/kamailio/src/core/parser/parse_subscription_state.h"

#ifdef __cplusplus
extern "C" {
#endif

// Function-under-test
void free_subscription_state(subscription_state_t **state);

int LLVMFuzzerTestOneInput_8(const uint8_t *data, size_t size) {
    // Allocate memory for subscription_state_t
    subscription_state_t *state = (subscription_state_t *)malloc(sizeof(subscription_state_t));
    if (state == NULL) {
        return 0; // Exit if memory allocation fails
    }

    // Initialize the state with some values based on the input data
    if (size > 0) {
        state->value = (substate_value_t)data[0]; // Example initialization
    } else {
        state->value = 0; // Default initialization
    }

    // Create a pointer to the state
    subscription_state_t *state_ptr = state;

    // Call the function-under-test
    free_subscription_state(&state_ptr);

    return 0;
}

#ifdef __cplusplus
}
#endif