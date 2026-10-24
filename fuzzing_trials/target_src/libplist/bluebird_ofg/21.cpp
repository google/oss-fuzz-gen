#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>  // Include for 'free'

extern "C" {
    #include "plist/plist.h"
}

extern "C" int LLVMFuzzerTestOneInput_21(const uint8_t *data, size_t size) {
    // Ensure there is input data to parse
    if (size == 0) {
        return 0;
    }

    // Attempt to parse the input data as a plist
    plist_t plist = NULL;
    plist_from_bin(reinterpret_cast<const char*>(data), static_cast<uint32_t>(size), &plist);

    // If plist parsing is successful, perform operations on the plist
    if (plist != NULL) {
        // Example operation: convert the plist to XML format
        char *xml = NULL;
        uint32_t xml_size = 0;
        plist_to_xml(plist, &xml, &xml_size);

        // Free the XML string if it was created
        if (xml != NULL) {
            free(xml);
        }

        // Clean up the plist object to avoid memory leaks

        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from plist_to_xml to plist_to_openstep

        // Begin mutation: Producer.SPLICE_MUTATOR - Spliced data flow from plist_to_xml to plist_date_val_compare using the plateau pool
        int ret_plist_date_val_compare_snkuh = plist_date_val_compare(plist, (int32_t )xml_size, (int32_t )xml_size);
        if (ret_plist_date_val_compare_snkuh < 0){
        	return 0;
        }
        // End mutation: Producer.SPLICE_MUTATOR
        
        plist_t ret_plist_copy_cncqz = plist_copy(plist);
        uint32_t ret_plist_dict_get_size_ocche = plist_dict_get_size(0);
        if (ret_plist_dict_get_size_ocche < 0){
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!xml) {
        	return 0;
        }
        plist_err_t ret_plist_to_openstep_nkhle = plist_to_openstep(ret_plist_copy_cncqz, &xml, &xml_size, (int )ret_plist_dict_get_size_ocche);
        // End mutation: Producer.APPEND_MUTATOR
        
        plist_free(plist);
    }

    return 0;
}
#ifdef INC_MAIN
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
int main(int argc, char *argv[])
{
    FILE *f;
    uint8_t *data = NULL;
    long size;

    if(argc < 2)
        exit(0);

    f = fopen(argv[1], "rb");
    if(f == NULL)
        exit(0);

    fseek(f, 0, SEEK_END);

    size = ftell(f);
    rewind(f);

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_21(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
