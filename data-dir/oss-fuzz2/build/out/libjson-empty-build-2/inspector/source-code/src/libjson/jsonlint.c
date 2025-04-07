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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <locale.h>
#include <getopt.h>
#include <errno.h>

#include "json.h"

char *indent_string = NULL;

char *string_of_errors[] =
{
	[JSON_ERROR_NO_MEMORY] = "out of memory",
	[JSON_ERROR_BAD_CHAR] = "bad character",
	[JSON_ERROR_POP_EMPTY] = "stack empty",
	[JSON_ERROR_POP_UNEXPECTED_MODE] = "pop unexpected mode",
	[JSON_ERROR_NESTING_LIMIT] = "nesting limit",
	[JSON_ERROR_DATA_LIMIT] = "data limit",
	[JSON_ERROR_COMMENT_NOT_ALLOWED] = "comment not allowed by config",
	[JSON_ERROR_UNEXPECTED_CHAR] = "unexpected char",
	[JSON_ERROR_UNICODE_MISSING_LOW_SURROGATE] = "missing unicode low surrogate",
	[JSON_ERROR_UNICODE_UNEXPECTED_LOW_SURROGATE] = "unexpected unicode low surrogate",
	[JSON_ERROR_COMMA_OUT_OF_STRUCTURE] = "error comma out of structure",
	[JSON_ERROR_CALLBACK] = "error in a callback",
	[JSON_ERROR_UTF8]     = "utf8 validation error"
};

static int printchannel(void *userdata, const char *data, uint32_t length)
{
	FILE *channel = userdata;
	int ret;
	ret = fwrite(data, length, 1, channel);
	if (ret != length)
		return 1;
	return 0;
}

static int prettyprint(void *userdata, int type, const char *data, uint32_t length)
{
	json_printer *printer = userdata;
	
	return json_print_pretty(printer, type, data, length);
}

FILE *open_filename(const char *filename, const char *opt, int is_input)
{
	FILE *input;
	if (strcmp(filename, "-") == 0)
		input = (is_input) ? stdin : stdout;
	else {
		input = fopen(filename, opt);
		if (!input) {
			fprintf(stderr, "error: cannot open %s: %s", filename, strerror(errno));
			return NULL;
		}
	}
	return input;
}

void close_filename(const char *filename, FILE *file)
{
	if (strcmp(filename, "-") != 0)
		fclose(file);
}

int process_file(json_parser *parser, FILE *input, int *retlines, int *retcols)
{
	char buffer[4096];
	int ret = 0;
	int32_t read;
	int lines, col, i;

	lines = 1;
	col = 0;
	while (1) {
		uint32_t processed;
		read = fread(buffer, 1, 4096, input);
		if (read <= 0)
			break;
		ret = json_parser_string(parser, buffer, read, &processed);
		for (i = 0; i < processed; i++) {
			if (buffer[i] == '\n') { col = 0; lines++; } else col++;
		}
		if (ret)
			break;
	}
	if (retlines) *retlines = lines;
	if (retcols) *retcols = col;
	return ret;
}

static int do_verify(json_config *config, const char *filename)
{
	FILE *input;
	json_parser parser;
	int ret;

	input = open_filename(filename, "r", 1);
	if (!input)
		return 2;

	/* initialize the parser structure. we don't need a callback in verify */
	ret = json_parser_init(&parser, config, NULL, NULL);
	if (ret) {
		fprintf(stderr, "error: initializing parser failed (code=%d): %s\n", ret, string_of_errors[ret]);
		return ret;
	}

	ret = process_file(&parser, input, NULL, NULL);
	if (ret)
		return 1;

	ret = json_parser_is_done(&parser);
	if (!ret)
		return 1;
	
	close_filename(filename, input);
	return 0;
}

static int do_parse(json_config *config, const char *filename)
{
	FILE *input;
	json_parser parser;
	int ret;
	int col, lines;

	input = open_filename(filename, "r", 1);
	if (!input)
		return 2;

	/* initialize the parser structure. we don't need a callback in verify */
	ret = json_parser_init(&parser, config, NULL, NULL);
	if (ret) {
		fprintf(stderr, "error: initializing parser failed (code=%d): %s\n", ret, string_of_errors[ret]);
		return ret;
	}

	ret = process_file(&parser, input, &lines, &col);
	if (ret) {
		fprintf(stderr, "line %d, col %d: [code=%d] %s\n",
		        lines, col, ret, string_of_errors[ret]);
		return 1;
	}

	ret = json_parser_is_done(&parser);
	if (!ret) {
		fprintf(stderr, "syntax error\n");
		return 1;
	}
	
	close_filename(filename, input);
	return 0;
}

static int do_format(json_config *config, const char *filename, const char *outputfile)
{
	FILE *input, *output;
	json_parser parser;
	json_printer printer;
	int ret;
	int col, lines;

	input = open_filename(filename, "r", 1);
	if (!input)
		return 2;

	output = open_filename(outputfile, "a+", 0);
	if (!output)
		return 2;

	/* initialize printer and parser structures */
	ret = json_print_init(&printer, printchannel, stdout);
	if (ret) {
		fprintf(stderr, "error: initializing printer failed: [code=%d] %s\n", ret, string_of_errors[ret]);
		return ret;
	}
	if (indent_string)
		printer.indentstr = indent_string;

	ret = json_parser_init(&parser, config, &prettyprint, &printer);
	if (ret) {
		fprintf(stderr, "error: initializing parser failed: [code=%d] %s\n", ret, string_of_errors[ret]);
		return ret;
	}

	ret = process_file(&parser, input, &lines, &col);
	if (ret) {
		fprintf(stderr, "line %d, col %d: [code=%d] %s\n",
		        lines, col, ret, string_of_errors[ret]);
		return 1;
	}

	ret = json_parser_is_done(&parser);
	if (!ret) {
		fprintf(stderr, "syntax error\n");
		return 1;
	}

	/* cleanup */
	json_parser_free(&parser);
	json_print_free(&printer);
	fwrite("\n", 1, 1, stdout);
	close_filename(filename, input);
	return 0;
}


struct json_val_elem {
	char *key;
	uint32_t key_length;
	struct json_val *val;
};

typedef struct json_val {
	int type;
	int length;
	union {
		char *data;
		struct json_val **array;
		struct json_val_elem **object;
	} u;
} json_val_t;

static void *tree_create_structure(int nesting, int is_object)
{
	json_val_t *v = malloc(sizeof(json_val_t));
	if (v) {
		/* instead of defining a new enum type, we abuse the
		 * meaning of the json enum type for array and object */
		if (is_object) {
			v->type = JSON_OBJECT_BEGIN;
			v->u.object = NULL;
		} else {
			v->type = JSON_ARRAY_BEGIN;
			v->u.array = NULL;
		}
		v->length = 0;
	}
	return v;
}

static char *memalloc_copy_length(const char *src, uint32_t n)
{
	char *dest;

	dest = calloc(n + 1, sizeof(char));
	if (dest)
		memcpy(dest, src, n);
	return dest;
}

static void *tree_create_data(int type, const char *data, uint32_t length)
{
	json_val_t *v;

	v = malloc(sizeof(json_val_t));
	if (v) {
		v->type = type;
		v->length = length;
		v->u.data = memalloc_copy_length(data, length);
		if (!v->u.data) {
			free(v);
			return NULL;
		}
	}
	return v;
}

static int tree_append(void *structure, char *key, uint32_t key_length, void *obj)
{
	json_val_t *parent = structure;
	if (key) {
		struct json_val_elem *objelem;

		if (parent->length == 0) {
			parent->u.object = calloc(1 + 1, sizeof(json_val_t *)); /* +1 for null */
			if (!parent->u.object)
				return 1;
		} else {
			uint32_t newsize = parent->length + 1 + 1; /* +1 for null */
			void *newptr;

			newptr = realloc(parent->u.object, newsize * sizeof(json_val_t *));
			if (!newptr)
				return -1;
			parent->u.object = newptr;
		}

		objelem = malloc(sizeof(struct json_val_elem));
		if (!objelem)
			return -1;

		objelem->key = memalloc_copy_length(key, key_length);
		objelem->key_length = key_length;
		objelem->val = obj;
		parent->u.object[parent->length++] = objelem;
		parent->u.object[parent->length] = NULL;
	} else {
		if (parent->length == 0) {
			parent->u.array = calloc(1 + 1, sizeof(json_val_t *)); /* +1 for null */
			if (!parent->u.array)
				return 1;
		} else {
			uint32_t newsize = parent->length + 1 + 1; /* +1 for null */
			void *newptr;

			newptr = realloc(parent->u.object, newsize * sizeof(json_val_t *));
			if (!newptr)
				return -1;
			parent->u.array = newptr;
		}
		parent->u.array[parent->length++] = obj;
		parent->u.array[parent->length] = NULL;
	}
	return 0;
}

static int do_tree(json_config *config, const char *filename, json_val_t **root_structure)
{
	FILE *input;
	json_parser parser;
	json_parser_dom dom;
	int ret;
	int col, lines;

	input = open_filename(filename, "r", 1);
	if (!input)
		return 2;

	ret = json_parser_dom_init(&dom, tree_create_structure, tree_create_data, tree_append);
	if (ret) {
		fprintf(stderr, "error: initializing helper failed: [code=%d] %s\n", ret, string_of_errors[ret]);
		return ret;
	}

	ret = json_parser_init(&parser, config, json_parser_dom_callback, &dom);
	if (ret) {
		fprintf(stderr, "error: initializing parser failed: [code=%d] %s\n", ret, string_of_errors[ret]);
		return ret;
	}

	ret = process_file(&parser, input, &lines, &col);
	if (ret) {
		fprintf(stderr, "line %d, col %d: [code=%d] %s\n",
		        lines, col, ret, string_of_errors[ret]);

		return 1;
	}

	ret = json_parser_is_done(&parser);
	if (!ret) {
		fprintf(stderr, "syntax error\n");
		return 1;
	}

	if (root_structure)
		*root_structure = dom.root_structure;

	/* cleanup */
	json_parser_free(&parser);
	close_filename(filename, input);
	return 0;
}

static int print_tree_iter(json_val_t *element, FILE *output)
{
	int i;
	if (!element) {
		fprintf(stderr, "error: no element in print tree\n");
		return -1;
	}

	switch (element->type) {
	case JSON_OBJECT_BEGIN:
		fprintf(output, "object begin (%d element)\n", element->length);
		for (i = 0; i < element->length; i++) {
			fprintf(output, "key: %s\n", element->u.object[i]->key);
			print_tree_iter(element->u.object[i]->val, output);
		}
		fprintf(output, "object end\n");
		break;
	case JSON_ARRAY_BEGIN:
		fprintf(output, "array begin\n");
		for (i = 0; i < element->length; i++) {
			print_tree_iter(element->u.array[i], output);
		}
		fprintf(output, "array end\n");
		break;
	case JSON_FALSE:
	case JSON_TRUE:
	case JSON_NULL:
		fprintf(output, "constant\n");
		break;
	case JSON_INT:
		fprintf(output, "integer: %s\n", element->u.data);
		break;
	case JSON_STRING:
		fprintf(output, "string: %s\n", element->u.data);
		break;
	case JSON_FLOAT:
		fprintf(output, "float: %s\n", element->u.data);
		break;
	default:
		break;
	}
	return 0;
}

static int print_tree(json_val_t *root_structure, char *outputfile)
{
	FILE *output;

	output = open_filename(outputfile, "a+", 0);
	if (!output)
		return 2;
	print_tree_iter(root_structure, output);
	close_filename(outputfile, output);
	return 0;
}

int usage(const char *argv0)
{
	printf("usage: %s [options] JSON-FILE(s)...\n", argv0);
	printf("\t--no-comments : disallow C and YAML comments in json file (default to both on)\n");
	printf("\t--no-yaml-comments : disallow YAML comment (default to on)\n");
	printf("\t--no-c-comments : disallow C comment (default to on)\n");
	printf("\t--format : pretty print the json file to stdout (unless -o specified)\n");
	printf("\t--verify : quietly verified if the json file is valid. exit 0 if valid, 1 if not\n");
	printf("\t--benchmark : quietly iterate multiples times over valid json files\n");
	printf("\t--max-nesting : limit the number of nesting in structure (default to no limit)\n");
	printf("\t--max-data : limit the number of characters of data (string/int/float) (default to no limit)\n");
	printf("\t--indent-string : set the string to use for indenting one level (default to 1 tab)\n");
	printf("\t--tree : build a tree (DOM)\n");
	printf("\t-o : output to a specific file instead of stdout\n");
	exit(0);
}

int main(int argc, char **argv)
{
	int format = 0, verify = 0, use_tree = 0, benchmarks = 0;
	int ret = 0, i;
	json_config config;
	char *output = "-";

	memset(&config, 0, sizeof(json_config));
	config.max_nesting = 0;
	config.max_data = 0;
	config.allow_c_comments = 1;
	config.allow_yaml_comments = 1;

	while (1) {
		int option_index;
		struct option long_options[] = {
			{ "no-comments", 0, 0, 0 },
			{ "no-yaml-comments", 0, 0, 0 },
			{ "no-c-comments", 0, 0, 0 },
			{ "format", 0, 0, 0 },
			{ "verify", 0, 0, 0 },
			{ "benchmark", 1, 0, 0 },
			{ "help", 0, 0, 0 },
			{ "max-nesting", 1, 0, 0 },
			{ "max-data", 1, 0, 0 },
			{ "indent-string", 1, 0, 0 },
			{ "tree", 0, 0, 0 },
			{ 0 },
		};
		int c = getopt_long(argc, argv, "o:", long_options, &option_index);
		if (c == -1)
			break;
		switch (c) {
		case 0: {
			const char *name = long_options[option_index].name;
			if (strcmp(name, "help") == 0)
				usage(argv[0]);
			else if (strcmp(name, "no-c-comments") == 0)
				config.allow_c_comments = 0;
			else if (strcmp(name, "no-yaml-comments") == 0)
				config.allow_yaml_comments = 0;
			else if (strcmp(name, "no-comments") == 0)
				config.allow_c_comments = config.allow_yaml_comments = 0;
			else if (strcmp(name, "format") == 0)
				format = 1;
			else if (strcmp(name, "verify") == 0)
				verify = 1;
			else if (strcmp(name, "max-nesting") == 0)
				config.max_nesting = atoi(optarg);
			else if (strcmp(name, "benchmark") == 0)
				benchmarks = atoi(optarg);
			else if (strcmp(name, "max-data") == 0)
				config.max_data = atoi(optarg);
			else if (strcmp(name, "indent-string") == 0)
				indent_string = strdup(optarg);
			else if (strcmp(name, "tree") == 0)
				use_tree = 1;
			break;
			}
		case 'o':
			output = strdup(optarg);
			break;
		default:
			break;
		}
	}
	if (!output)
		output = "-";
	if (optind >= argc)
		usage(argv[0]);

	if (benchmarks > 0) {
		for (i = 0; i < benchmarks; i++) {
			if (use_tree) {
				json_val_t *root_structure;
				ret = do_tree(&config, argv[optind], &root_structure);
			} else {
				ret = do_verify(&config, argv[optind]);
			}
			if (ret)
				exit(ret);
		}
		exit(0);
	}

	for (i = optind; i < argc; i++) {
		if (use_tree) {
			json_val_t *root_structure;
			ret = do_tree(&config, argv[i], &root_structure);
			if (ret)
				exit(ret);
			if (!verify)
				print_tree(root_structure, output);
		} else {
			if (format)
				ret = do_format(&config, argv[i], output);
			else if (verify)
				ret = do_verify(&config, argv[i]);
			else
				ret = do_parse(&config, argv[i]);
		}
		if (ret)
			exit(ret);
	}
	return ret;
}
