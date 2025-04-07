/*
 * Copyright (C) 2009-2011 Vincent Hanquez <vincent@snarc.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 or version 3.0 only.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef JSON_H
#define JSON_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>

#if defined(_MSC_VER) && (_MSC_VER < 1600)
// MSVC does not include stdint.h before version 10.0
typedef unsigned __int8 uint8_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int32 uint32_t;
#else
#include <stdint.h>
#endif

#define JSON_MAJOR 	1
#define JSON_MINOR	0
#define JSON_VERSION	(JSON_MAJOR * 100 + JSON_MINOR)

typedef enum 
{
	JSON_NONE,
	JSON_ARRAY_BEGIN,
	JSON_OBJECT_BEGIN,
	JSON_ARRAY_END,
	JSON_OBJECT_END,
	JSON_INT,
	JSON_FLOAT,
	JSON_STRING,
	JSON_KEY,
	JSON_TRUE,
	JSON_FALSE,
	JSON_NULL,
	JSON_BSTRING,
} json_type;

typedef enum
{
	/* SUCCESS = 0 */
	/* running out of memory */
	JSON_ERROR_NO_MEMORY = 1,
	/* character < 32, except space newline tab */
	JSON_ERROR_BAD_CHAR,
	/* trying to pop more object/array than pushed on the stack */
	JSON_ERROR_POP_EMPTY,
	/* trying to pop wrong type of mode. popping array in object mode, vice versa */
	JSON_ERROR_POP_UNEXPECTED_MODE,
	/* reach nesting limit on stack */
	JSON_ERROR_NESTING_LIMIT,
	/* reach data limit on buffer */
	JSON_ERROR_DATA_LIMIT,
	/* comment are not allowed with current configuration */
	JSON_ERROR_COMMENT_NOT_ALLOWED,
	/* unexpected char in the current parser context */
	JSON_ERROR_UNEXPECTED_CHAR,
	/* unicode low surrogate missing after high surrogate */
	JSON_ERROR_UNICODE_MISSING_LOW_SURROGATE,
	/* unicode low surrogate missing without previous high surrogate */
	JSON_ERROR_UNICODE_UNEXPECTED_LOW_SURROGATE,
	/* found a comma not in structure (array/object) */
	JSON_ERROR_COMMA_OUT_OF_STRUCTURE,
	/* callback returns error */
	JSON_ERROR_CALLBACK,
	/* utf8 stream is invalid */
	JSON_ERROR_UTF8,
} json_error;

#define LIBJSON_DEFAULT_STACK_SIZE 256
#define LIBJSON_DEFAULT_BUFFER_SIZE 4096

typedef int (*json_parser_callback)(void *userdata, int type, const char *data, uint32_t length);
typedef int (*json_printer_callback)(void *userdata, const char *s, uint32_t length);

typedef struct {
	uint32_t buffer_initial_size;
	uint32_t max_nesting;
	uint32_t max_data;
	int allow_c_comments;
	int allow_yaml_comments;
	void * (*user_calloc)(size_t nmemb, size_t size);
	void * (*user_realloc)(void *ptr, size_t size);
} json_config;

typedef struct json_parser {
	json_config config;

	/* SAJ callback */
	json_parser_callback callback;
	void *userdata;

	/* parser state */
	uint8_t state;
	uint8_t save_state;
	uint8_t expecting_key;
	uint8_t utf8_multibyte_left;
	uint16_t unicode_multi;
	json_type type;

	/* state stack */
	uint8_t *stack;
	uint32_t stack_offset;
	uint32_t stack_size;

	/* parse buffer */
	char *buffer;
	uint32_t buffer_size;
	uint32_t buffer_offset;
} json_parser;

typedef struct json_printer {
	json_printer_callback callback;
	void *userdata;

	char *indentstr;
	int indentlevel;
	int afterkey;
	int enter_object;
	int first;
} json_printer;

/** json_parser_init initialize a parser structure taking a config,
 * a config and its userdata.
 * return JSON_ERROR_NO_MEMORY if memory allocation failed or SUCCESS.  */
int json_parser_init(json_parser *parser, json_config *cfg,
                     json_parser_callback callback, void *userdata);

/** json_parser_free freed memory structure allocated by the parser */
int json_parser_free(json_parser *parser);

/** json_parser_string append a string s with a specific length to the parser
 * return 0 if everything went ok, a JSON_ERROR_* otherwise.
 * the user can supplied a valid processed pointer that will
 * be fill with the number of processed characters before returning */
int json_parser_string(json_parser *parser, const char *string,
                       uint32_t length, uint32_t *processed);

/** json_parser_char append one single char to the parser
 * return 0 if everything went ok, a JSON_ERROR_* otherwise */
int json_parser_char(json_parser *parser, unsigned char next_char);

/** json_parser_is_done return 0 is the parser isn't in a finish state. !0 if it is */
int json_parser_is_done(json_parser *parser);

/** json_print_init initialize a printer context. always succeed */
int json_print_init(json_printer *printer, json_printer_callback callback, void *userdata);

/** json_print_free free a printer context
 * doesn't do anything now, but in future print_init could allocate memory */
int json_print_free(json_printer *printer);

/** json_print_pretty pretty print the passed argument (type/data/length). */
int json_print_pretty(json_printer *printer, int type, const char *data, uint32_t length);

/** json_print_raw prints without eye candy the passed argument (type/data/length). */
int json_print_raw(json_printer *printer, int type, const char *data, uint32_t length);

/** json_print_args takes multiple types and pass them to the printer function
 * array, object and constants doesn't take a string and length argument.
 * int, float, key, string need to be followed by a pointer to char and then a length.
 * if the length argument is -1, then the strlen function will use on the string argument.
 * the function call should always be terminated by -1 */
int json_print_args(json_printer *, int (*f)(json_printer *, int, const char *, uint32_t), ...);

/** callback from the parser_dom callback to create object and array */
typedef void * (*json_parser_dom_create_structure)(int, int);

/** callback from the parser_dom callback to create data values */
typedef void * (*json_parser_dom_create_data)(int, const char *, uint32_t);

/** callback from the parser helper callback to append a value to an object or array value
 * append(parent, key, key_length, val); */
typedef int (*json_parser_dom_append)(void *, char *, uint32_t, void *);

/** the json_parser_dom permits to create a DOM like tree easily through the
 * use of 3 callbacks where the user can choose the representation of the JSON values */
typedef struct json_parser_dom
{
	/* object stack */
	struct stack_elem { void *val; char *key; uint32_t key_length; } *stack;
	uint32_t stack_size;
	uint32_t stack_offset;

	/* overridable memory allocator */
	void * (*user_calloc)(size_t nmemb, size_t size);
	void * (*user_realloc)(void *ptr, size_t size);

	/* returned root structure (object or array) */
	void *root_structure;

	/* callbacks */
	json_parser_dom_create_structure create_structure;
	json_parser_dom_create_data create_data;
	json_parser_dom_append append;
} json_parser_dom;

/** initialize a parser dom structure with the necessary callbacks */
int json_parser_dom_init(json_parser_dom *helper,
                         json_parser_dom_create_structure create_structure,
                         json_parser_dom_create_data create_data,
                         json_parser_dom_append append);
/** free memory allocated by the DOM callback helper */
int json_parser_dom_free(json_parser_dom *ctx);

/** helper to parser callback that arrange parsing events into comprehensive JSON data structure */
int json_parser_dom_callback(void *userdata, int type, const char *data, uint32_t length);

#ifdef __cplusplus
}
#endif

#endif /* JSON_H */
