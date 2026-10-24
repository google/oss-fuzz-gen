#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <libical/ical.h>

extern "C" int LLVMFuzzerTestOneInput_8(char *fuzzData, size_t size)
{
	
        

   icalcomponent* icalcomponent_new_from_stringval1 = icalcomponent_new_from_string(fuzzData);

	if(!icalcomponent_new_from_stringval1){
		fprintf(stderr, "err");
		exit(0);	}
   icalcomponent* icalcomponent_cloneval1 = icalcomponent_clone(icalcomponent_new_from_stringval1);
	if(!icalcomponent_cloneval1){
		fprintf(stderr, "err");
		exit(0);	}
   icalcomponent_normalize(icalcomponent_cloneval1);
   icalcomponent_free(icalcomponent_cloneval1);
   return 0;
}
