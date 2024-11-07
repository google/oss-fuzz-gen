/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>

#include <isc/buffer.h>
#include <isc/commandline.h>
#include <isc/file.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/message.h>

#include "fuzz.h"

bool debug = false;

static isc_mem_t *mctx = NULL;
static uint8_t *output = NULL;
static size_t output_len = 1024;
static uint8_t render_buf[64 * 1024 - 1];

int
LLVMFuzzerInitialize(int *argc ISC_ATTR_UNUSED, char ***argv ISC_ATTR_UNUSED) {
	isc_mem_create(&mctx);
	output = isc_mem_get(mctx, output_len);

	return (0);
}

static isc_result_t
parse_message(isc_buffer_t *input, dns_message_t **messagep) {
	isc_result_t result;
	dns_message_t *message = NULL;

	dns_message_create(mctx, NULL, NULL, DNS_MESSAGE_INTENTPARSE, &message);

	result = dns_message_parse(message, input, DNS_MESSAGEPARSE_BESTEFFORT);
	if (result == DNS_R_RECOVERABLE) {
		result = ISC_R_SUCCESS;
	}

	if (result == ISC_R_SUCCESS && messagep != NULL) {
		*messagep = message;
	} else {
		dns_message_detach(&message);
	}

	return (result);
}

static isc_result_t
print_message(dns_message_t *message) {
	isc_result_t result;
	isc_buffer_t buffer;

	do {
		isc_buffer_init(&buffer, output, output_len);
		result = dns_message_totext(message, &dns_master_style_debug, 0,
					    &buffer);
		if (result == ISC_R_NOSPACE) {
			isc_mem_put(mctx, output, output_len);
			output_len *= 2;
			output = isc_mem_get(mctx, output_len);
			continue;
		}
	} while (result == ISC_R_NOSPACE);

	if (debug) {
		fprintf(stderr, "%.*s\n", (int)isc_buffer_usedlength(&buffer),
			output);
	}

	return (result);
}

#define CHECKRESULT(r, f)                 \
	{                                 \
		r = (f);                  \
		if (r != ISC_R_SUCCESS) { \
			goto cleanup;     \
		}                         \
	}

static isc_result_t
render_message(dns_message_t **messagep) {
	isc_result_t result;
	dns_message_t *message = *messagep;
	isc_buffer_t buffer;
	dns_compress_t cctx;

	isc_buffer_init(&buffer, render_buf, sizeof(render_buf));

	message->from_to_wire = DNS_MESSAGE_INTENTRENDER;
	for (size_t i = 0; i < DNS_SECTION_MAX; i++) {
		message->counts[i] = 0;
	}

	dns_compress_init(&cctx, mctx, 0);

	CHECKRESULT(result, dns_message_renderbegin(message, &cctx, &buffer));

	CHECKRESULT(result, dns_message_rendersection(message,
						      DNS_SECTION_QUESTION, 0));

	CHECKRESULT(result,
		    dns_message_rendersection(message, DNS_SECTION_ANSWER, 0));
	CHECKRESULT(result, dns_message_rendersection(
				    message, DNS_SECTION_AUTHORITY, 0));

	CHECKRESULT(result, dns_message_rendersection(
				    message, DNS_SECTION_ADDITIONAL, 0));

	dns_message_renderend(message);

	dns_compress_invalidate(&cctx);

	message->from_to_wire = DNS_MESSAGE_INTENTPARSE;

	dns_message_detach(messagep);

	result = parse_message(&buffer, messagep);

	return (result);

cleanup:
	dns_compress_invalidate(&cctx);
	return (result);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	isc_buffer_t buffer;
	isc_result_t result;
	dns_message_t *message = NULL;

	if (size > 65535) {
		return (0);
	}

	isc_buffer_constinit(&buffer, data, size);
	isc_buffer_add(&buffer, size);
	isc_buffer_setactive(&buffer, size);

	result = parse_message(&buffer, &message);
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}

	result = print_message(message);
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}

	result = render_message(&message);
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}

	result = print_message(message);
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}

cleanup:
	if (message != NULL) {
		dns_message_detach(&message);
	}

	return (0);
}
