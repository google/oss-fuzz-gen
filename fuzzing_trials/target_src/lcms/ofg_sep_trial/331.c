#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_331(const uint8_t *data, size_t size) {
    // Declare and initialize a cmsSEQ object
    cmsSEQ *seq = cmsAllocProfileSequenceDescription(NULL, 1);

    if (seq != NULL) {
        // Fill the sequence with some data based on the input
        for (size_t i = 0; i < size && i < seq->n; i++) {
            seq->seq[i].ProfileID.ID8[0] = data[i];
            seq->seq[i].ProfileID.ID8[1] = data[i];
            seq->seq[i].ProfileID.ID8[2] = data[i];
            seq->seq[i].ProfileID.ID8[3] = data[i];
            seq->seq[i].ProfileID.ID8[4] = data[i];
            seq->seq[i].ProfileID.ID8[5] = data[i];
            seq->seq[i].ProfileID.ID8[6] = data[i];
            seq->seq[i].ProfileID.ID8[7] = data[i];
            seq->seq[i].ProfileID.ID8[8] = data[i];
            seq->seq[i].ProfileID.ID8[9] = data[i];
            seq->seq[i].ProfileID.ID8[10] = data[i];
            seq->seq[i].ProfileID.ID8[11] = data[i];
            seq->seq[i].ProfileID.ID8[12] = data[i];
            seq->seq[i].ProfileID.ID8[13] = data[i];
            seq->seq[i].ProfileID.ID8[14] = data[i];
            seq->seq[i].ProfileID.ID8[15] = data[i];
        }

        // Call the function under test
        cmsFreeProfileSequenceDescription(seq);
    }

    return 0;
}