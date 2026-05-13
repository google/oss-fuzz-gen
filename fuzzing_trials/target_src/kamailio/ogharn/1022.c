#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <hf.h>
#include <keys.h>
#include <msg_parser.h>
#include <parse_addr_spec.h>
#include <parse_allow.h>
#include <parse_body.h>
#include <parse_content.h>
#include <parse_cseq.h>
#include <parse_date.h>
#include <parse_def.h>
#include <parse_disposition.h>
#include <parse_diversion.h>
#include <parse_event.h>
#include <parse_expires.h>
#include <parse_fline.h>
#include <parse_from.h>
#include <parse_hname2.h>
#include <parse_identity.h>
#include <parse_identityinfo.h>
#include <parse_methods.h>
#include <parse_nameaddr.h>
#include <parse_option_tags.h>
#include <parse_param.h>
#include <parse_ppi_pai.h>
#include <parse_privacy.h>
#include <parse_refer_to.h>
#include <parse_require.h>
#include <parse_retry_after.h>
#include <parse_rpid.h>
#include <parse_rr.h>
#include <parse_sipifmatch.h>
#include <parse_subscription_state.h>
#include <parse_supported.h>
#include <parse_to.h>
#include <parse_uri.h>
#include <parse_via.h>
#include <parser_f.h>

int LLVMFuzzerTestOneInput_1022(char *fuzzData, size_t size)
{
	

   char* parse_viavar1[size+1];
	sprintf(parse_viavar1, "/tmp/u2u8h");
   struct via_body parse_viavar2;
	memset(&parse_viavar2, 0, sizeof(parse_viavar2));

   struct msg_start parse_first_linevar2;
	memset(&parse_first_linevar2, 0, sizeof(parse_first_linevar2));

   str parse_params2var0;
	memset(&parse_params2var0, 0, sizeof(parse_params2var0));

   param_hooks_t parse_params2var2;
	memset(&parse_params2var2, 0, sizeof(parse_params2var2));

   param_t* parse_params2var3;
	memset(&parse_params2var3, 0, sizeof(parse_params2var3));

   char* parse_viaval1 = parse_via(fuzzData, parse_viavar1, &parse_viavar2);
	if(!parse_viaval1){
		fprintf(stderr, "err");
		exit(0);	}
   char* parse_first_lineval1 = parse_first_line(parse_viaval1, SUBTYPE_CPIM, &parse_first_linevar2);
	if(!parse_first_lineval1){
		fprintf(stderr, "err");
		exit(0);	}
	if(!*parse_viaval1){
		fprintf(stderr, "err");
		exit(0);	}
   int parse_params2val1 = parse_params2(&parse_params2var0, CLASS_EVENT_DIALOG, &parse_params2var2, &parse_params2var3, *parse_viaval1);
	if((int)parse_params2val1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int is_2rrval1 = is_2rr(&parse_params2var0);
	if((int)is_2rrval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
