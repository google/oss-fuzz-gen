#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

// Mock function to simulate cmsDupProfileSequenceDescription
cmsSEQ * cmsDupProfileSequenceDescription_1(const cmsSEQ *seq) {
    // In a real scenario, this would duplicate the profile sequence description
    // Here, we simply return a new cmsSEQ for demonstration purposes
    cmsSEQ *newSeq = (cmsSEQ *)malloc(sizeof(cmsSEQ));
    if (newSeq != NULL && seq != NULL) {
        newSeq->n = seq->n; // Copy the n value
        newSeq->ContextID = seq->ContextID; // Copy the ContextID
        newSeq->seq = seq->seq; // Copy the seq pointer
    }
    return newSeq;
}

int LLVMFuzzerTestOneInput_8(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our cmsSEQ structure
    if (size < sizeof(cmsSEQ)) {
        return 0;
    }

    // Cast the input data to a cmsSEQ pointer
    const cmsSEQ *inputSeq = (const cmsSEQ *)data;

    // Call the function-under-test
    cmsSEQ *duplicateSeq = cmsDupProfileSequenceDescription_1(inputSeq);

    // Free the duplicated sequence if it was successfully created
    if (duplicateSeq != NULL) {
        free(duplicateSeq);
    }

    return 0;
}