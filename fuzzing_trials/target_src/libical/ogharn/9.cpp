#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <libical/ical.h>

extern "C" int LLVMFuzzerTestOneInput_9(char *fuzzData, size_t size)
{
	
        

   struct icaltimetype icalcomponent_set_dtstampvar0;
	memset(&icalcomponent_set_dtstampvar0, 0, (sizeof icalcomponent_set_dtstampvar0));

   icalcomponent* icalcomponent_new_from_stringval1 = icalcomponent_new_from_string(fuzzData);

	if(!icalcomponent_new_from_stringval1){
		fprintf(stderr, "err");
		exit(0);	}
   icalcomponent_set_dtstamp(icalcomponent_new_from_stringval1, icalcomponent_set_dtstampvar0);
   return 0;
}
