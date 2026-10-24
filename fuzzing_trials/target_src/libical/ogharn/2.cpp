#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <libical/ical.h>

extern "C" int LLVMFuzzerTestOneInput_2(char *fuzzData, size_t size)
{
	
        

   icalcomponent* icalcomponent_new_from_stringval1 = icalcomponent_new_from_string(fuzzData);

	if(!icalcomponent_new_from_stringval1){
		fprintf(stderr, "err");
		exit(0);	}
   char* icalcomponent_as_ical_stringval1 = icalcomponent_as_ical_string(icalcomponent_new_from_stringval1);
	if(!icalcomponent_as_ical_stringval1){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
