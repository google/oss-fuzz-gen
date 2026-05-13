#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <plist/plist.h>

extern "C" int LLVMFuzzerTestOneInput_59(char *fuzzData, size_t size)
{
	

   plist_format_t plist_from_memoryoverload3var3;
	memset(&plist_from_memoryoverload3var3, 0, sizeof(plist_from_memoryoverload3var3));

   plist_dict_iter plist_dict_next_itemvar1;
	memset(&plist_dict_next_itemvar1, 0, sizeof(plist_dict_next_itemvar1));

   plist_t plist_new_dictval1 = plist_new_dict();
   plist_err_t plist_from_memoryoverload3val1 = plist_from_memory(fuzzData, size, &plist_new_dictval1, &plist_from_memoryoverload3var3);
	if(plist_from_memoryoverload3val1 != PLIST_ERR_SUCCESS){
		fprintf(stderr, "err");
		exit(0);	}
   plist_dict_merge(&plist_new_dictval1, plist_new_dictval1);
   plist_dict_next_item(NULL, plist_dict_next_itemvar1, NULL, &plist_new_dictval1);
	if(!fuzzData){
		fprintf(stderr, "err");
		exit(0);	}
   plist_dict_next_item(plist_new_dictval1, plist_dict_next_itemvar1, &fuzzData, NULL);
   return 0;
}
