/*******************************************************************************
 * argtable3: Declares the main interfaces of the library
 *
 * This file is part of the argtable3 library.
 *
 * Copyright (C) 1998-2001,2003-2011,2013 Stewart Heitmann
 * <sheitmann@users.sourceforge.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of STEWART HEITMANN nor the  names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL STEWART HEITMANN BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/

#ifndef ARGTABLE3
#define ARGTABLE3

#include <stdio.h> /* FILE */
#include <time.h>  /* struct tm */

#ifdef __cplusplus
extern "C" {
#endif

#define ARG_REX_ICASE 1

/* Maximum length of the command name */
#ifndef ARG_CMD_NAME_LEN
#define ARG_CMD_NAME_LEN 100
#endif /* ARG_CMD_NAME_LEN */

/* Maximum length of the command description */
#ifndef ARG_CMD_DESCRIPTION_LEN
#define ARG_CMD_DESCRIPTION_LEN 256
#endif /* ARG_CMD_DESCRIPTION_LEN */

/**
 * Bit masks for `arg_hdr.flag`.
 */
enum arg_hdr_flag {
    ARG_TERMINATOR = 0x1,
    ARG_HASVALUE = 0x2,
    ARG_HASOPTVALUE = 0x4
};

#if defined(_WIN32)
  #if defined(argtable3_EXPORTS)
    #define ARG_EXTERN __declspec(dllexport)
  #elif defined(argtable3_IMPORTS)
    #define ARG_EXTERN __declspec(dllimport)
  #else
    #define ARG_EXTERN
  #endif
#else
  #define ARG_EXTERN
#endif

typedef struct _internal_arg_dstr* arg_dstr_t;
typedef void* arg_cmd_itr_t;

typedef void(arg_resetfn)(void* parent);
typedef int(arg_scanfn)(void* parent, const char* argval);
typedef int(arg_checkfn)(void* parent);
typedef void(arg_errorfn)(void* parent, arg_dstr_t ds, int error, const char* argval, const char* progname);
typedef void(arg_dstr_freefn)(char* buf);
typedef int(arg_cmdfn)(int argc, char* argv[], arg_dstr_t res, void* ctx);
typedef int(arg_comparefn)(const void* k1, const void* k2);

/**
 * Defines properties that are common to all `arg_xxx` structs.
 *
 * The argtable library requires each `arg_xxx` struct to have an `arg_hdr`
 * struct as its first data member. The argtable library functions then use this
 * data to identify the properties of the command line option, such as its
 * option tags, datatype string, and glossary strings, and so on.
 *
 * Moreover, the `arg_hdr` struct contains pointers to custom functions that are
 * provided by each `arg_xxx` struct which perform the tasks of parsing that
 * particular `arg_xxx` arguments, performing post-parse checks, and reporting
 * errors. These functions are private to the individual `arg_xxx` source code
 * and are the pointer to them are initiliased by that `arg_xxx` struct's
 * constructor function. The user could alter them after construction if
 * desired, but the original intention is for them to be set by the constructor
 * and left unaltered.
 */
typedef struct arg_hdr {
    char flag;             /**< Modifier flags: available options are in enum `arg_hdr_flag`. */
    const char* shortopts; /**< String defining the short options */
    const char* longopts;  /**< String defiing the long options */
    const char* datatype;  /**< Description of the argument data type */
    const char* glossary;  /**< Description of the option as shown by arg_print_glossary function */
    int mincount;          /**< Minimum number of occurences of this option accepted */
    int maxcount;          /**< Maximum number of occurences if this option accepted */
    void* parent;          /**< Pointer to parent arg_xxx struct */
    arg_resetfn* resetfn;  /**< Pointer to parent arg_xxx reset function */
    arg_scanfn* scanfn;    /**< Pointer to parent arg_xxx scan function */
    arg_checkfn* checkfn;  /**< Pointer to parent arg_xxx check function */
    arg_errorfn* errorfn;  /**< Pointer to parent arg_xxx error function */
    void* priv;            /**< Pointer to private header data for use by arg_xxx functions */
} arg_hdr_t;

/**
 * Contains remarks argument information, which is used to add an extra line to
 * the syntax or glossary output.
 */
typedef struct arg_rem {
    struct arg_hdr hdr; /**< The mandatory argtable header struct */
} arg_rem_t;

/**
 * Contains const-string-typed argument information.
 */
typedef struct arg_lit {
    struct arg_hdr hdr; /**< The mandatory argtable header struct */
    int count;          /**< Number of matching command line args */
} arg_lit_t;

/**
 * Contains int-typed argument information.
 */
typedef struct arg_int {
    struct arg_hdr hdr; /**< The mandatory argtable header struct */
    int count;          /**< Number of matching command line args */
    int* ival;          /**< Array of parsed argument values */
} arg_int_t;

/**
 * Contains double-typed argument information.
 */
typedef struct arg_dbl {
    struct arg_hdr hdr; /**< The mandatory argtable header struct */
    int count;          /**< Number of matching command line args */
    double* dval;       /**< Array of parsed argument values */
} arg_dbl_t;

/**
 * Contains string-typed argument information.
 */
typedef struct arg_str {
    struct arg_hdr hdr; /**< The mandatory argtable header struct */
    int count;          /**< Number of matching command line args */
    const char** sval;  /**< Array of parsed argument values */
} arg_str_t;

/**
 * Contains regex-typed argument information.
 */
typedef struct arg_rex {
    struct arg_hdr hdr; /**< The mandatory argtable header struct */
    int count;          /**< Number of matching command line args */
    const char** sval;  /**< Array of parsed argument values */
} arg_rex_t;

/**
 * Contains file-typed argument information.
 */
typedef struct arg_file {
    struct arg_hdr hdr;     /**< The mandatory argtable header struct */
    int count;              /**< Number of matching command line args*/
    const char** filename;  /**< Array of parsed filenames  (eg: /home/foo.bar) */
    const char** basename;  /**< Array of parsed basenames  (eg: foo.bar) */
    const char** extension; /**< Array of parsed extensions (eg: .bar) */
} arg_file_t;

/**
 * Contains date-typed argument information.
 */
typedef struct arg_date {
    struct arg_hdr hdr; /**< The mandatory argtable header struct */
    const char* format; /**< strptime format string used to parse the date */
    int count;          /**< Number of matching command line args */
    struct tm* tmval;   /**< Array of parsed time values */
} arg_date_t;

enum { ARG_ELIMIT = 1, ARG_EMALLOC, ARG_ENOMATCH, ARG_ELONGOPT, ARG_EMISSARG };

/**
 * Contains parser errors and terminates the argument table.
 */
typedef struct arg_end {
    struct arg_hdr hdr;  /**< The mandatory argtable header struct */
    int count;           /**< Number of errors encountered */
    int* error;          /**< Array of error codes */
    void** parent;       /**< Array of pointers to offending arg_xxx struct */
    const char** argval; /**< Array of pointers to offending argv[] string */
} arg_end_t;

/**
 * Contains sub-command information.
 */
typedef struct arg_cmd_info {
    char name[ARG_CMD_NAME_LEN];               /**< Sub-command name */
    char description[ARG_CMD_DESCRIPTION_LEN]; /**< A short description */
    arg_cmdfn* proc;                           /**< Sub-command procedure */
    void* ctx;                                 /**< Sub-command context */
} arg_cmd_info_t;

/**** arg_xxx constructor functions *********************************/

/**
 * Creates a data type in the syntax or add a new line in the glossary.
 *
 * Sometimes you will wish to add extra lines of text to the glossary, or even
 * put your own text into the syntax string generated by arg_print_syntax. You
 * can add newline characters to your argument table strings if you wish, but it
 * soon gets ugly. A better way is to add `arg_rem` structs to your argument
 * table. They are dummy argument table entries in the sense that they do not
 * alter the argument parsing but their datatype and glossary strings do appear
 * in the output generated by the arg_print_syntax and arg_print_glossary
 * functions. The name `arg_rem` is for *remark*, and it is inspired by the
 * `REM` statement used in the BASIC language.
 *
 * For example, in the `mv` example program, we use `arg_rem` to add additional
 * lines for the `-u|--update` option in the glossary:
 * ```
 * struct arg_lit *update  = arg_litn("u", "update", 0, 1, "copy only when SOURCE files are");
 * struct arg_rem *update1 = arg_rem(NULL,                 "  newer than destination files");
 * struct arg_rem *update1 = arg_rem(NULL,                 "  or when destination files");
 * struct arg_rem *update2 = arg_rem(NULL,                 "  are missing");
 * ```
 *
 * which will make the glossay look like:
 * ```
 *   -u, --update                   copy only when SOURCE files are
 *                                    newer than destination files
 *                                    or when the destination files
 *                                    are missing
 * ```
 *
 * We also use `arg_rem` to add a data type entry for the ordinary argument in
 * the syntax:
 * ```
 * struct arg_rem *dest = arg_rem ("DEST|DIRECTORY", NULL);
 * ```
 *
 * which will make the syntax look like:
 * ```
 * $ mv --help
 * Usage: mv [-bfiuv] [--backup=[CONTROL]] [--reply={yes,no,query}]
 * [--strip-trailing-slashes] [-S SUFFIX] [--target-directory=DIRECTORY]
 * [--help] [--version] SOURCE [SOURCE]... DEST|DIRECTORY
 * ```
 *
 * @param datatype A pointer to a WNDCLASSEX structure. You must fill the
 *   structure with the appropriate class attributes before passing it to the
 *   function.
 * @param glossary The second one, which follows @p datatype.
 *
 * @return
 *   If successful, `arg_rem` returns a pointer to the allocated `struct
 *   arg_rem`. Otherwise, `arg_rem` returns `NULL` if there is insufficient
 *   memory available.
 */
ARG_EXTERN struct arg_rem* arg_rem(const char* datatype, const char* glossary);

/**
 * Creates a literal argument that does not take an argument value.
 *
 * A literal argument is usually used to express a boolean flag, such as `-h`
 * and `--version`. However, since a literal argument can appear multiple times
 * in a command line, we can use the number of occurrence as an implicit
 * argument value.
 *
 * For example, the `tar` utility uses `--verbose` or `-v` to show the files
 * being worked on as `tar` is creating an archive:
 * ```
 * $ tar -cvf afiles.tar apple angst aspic
 * apple
 * angst
 * aspic
 * ```
 *
 * Each occurrence of `--verbose` or `-v` on the command line increases the
 * verbosity level by one. Therefore, if you need more details on the output,
 * specify it twice:
 * ```
 * $ tar -cvvf afiles.tar apple angst aspic
 * -rw-r--r-- gray/staff    62373 2006-06-09 12:06 apple
 * -rw-r--r-- gray/staff    11481 2006-06-09 12:06 angst
 * -rw-r--r-- gray/staff    23152 2006-06-09 12:06 aspic
 * ```
 *
 * `arg_lit0` is a helper function of `arg_litn` when we specify `mincount` to
 * `0` and `maxcount` to `1`. `arg_lit1` is a helper function of `arg_litn` when
 * we specify both `mincount` and `maxcount` to `1`. These helper functions are
 * considered deprecated, but they will be kept for backward compatibility. You
 * should use `arg_litn` in new projects, since it is more explicit and easier
 * to understand.
 *
 * **Example** Creating literal arguments
 * ```
 * struct arg_lit *list    = arg_litn("lL",NULL,           0, 1, "list files");
 * struct arg_lit *verbose = arg_litn("v","verbose,debug", 0, 3, "verbosity level");
 * struct arg_lit *help    = arg_litn("h","help",          0, 1, "print this help");
 * struct arg_lit *version = arg_litn(NULL,"version",      0, 1, "print version info");
 * ```
 *
 * @param shortopts A string of single characters, and each character is an
 *        alternative short option name of the argument. For example, `"kKx"`
 *        means you can use `-k`, `-K`, or `-x` as the short options. If you
 *        don't want to use any short option, pass `NULL` to this parameter.
 * @param longopts A string of alternative long option names of the argument,
 *        separated by commas. For example, `"verbose,debug"` means you can use
 *        `--verbose` or `--debug` as the long options. If you don't want to use
 *        any long option, pass `NULL` to this parameter.
 * @param mincount The minimum number of the argument. Setting it to `0` means
 *        that the argument is optional.
 * @param maxcount The maximum number of the argument. The value of `maxcount`
 *        decides how much memory we need to allocate to store argument values.
 *        Choose a reasonable value, so we don't increase unnecessary memory
 *        usage.
 * @param glossary A short description of the argument. If you don't want to
 *        display this argument in the glossary, pass `NULL` to this parameter.
 *
 * @return
 *   If successful, `arg_litn`, `arg_lit0`, and `arg_lit1` return a pointer to
 *   the allocated `struct arg_lit`. Otherwise, these functions return `NULL` if
 *   there is insufficient memory available.
 */
ARG_EXTERN struct arg_lit* arg_litn(const char* shortopts, const char* longopts, int mincount, int maxcount, const char* glossary);
ARG_EXTERN struct arg_lit* arg_lit0(const char* shortopts, const char* longopts, const char* glossary);
ARG_EXTERN struct arg_lit* arg_lit1(const char* shortopts, const char* longopts, const char* glossary);

ARG_EXTERN struct arg_int* arg_int0(const char* shortopts, const char* longopts, const char* datatype, const char* glossary);
ARG_EXTERN struct arg_int* arg_int1(const char* shortopts, const char* longopts, const char* datatype, const char* glossary);
ARG_EXTERN struct arg_int* arg_intn(const char* shortopts, const char* longopts, const char* datatype, int mincount, int maxcount, const char* glossary);

ARG_EXTERN struct arg_dbl* arg_dbl0(const char* shortopts, const char* longopts, const char* datatype, const char* glossary);
ARG_EXTERN struct arg_dbl* arg_dbl1(const char* shortopts, const char* longopts, const char* datatype, const char* glossary);
ARG_EXTERN struct arg_dbl* arg_dbln(const char* shortopts, const char* longopts, const char* datatype, int mincount, int maxcount, const char* glossary);

ARG_EXTERN struct arg_str* arg_str0(const char* shortopts, const char* longopts, const char* datatype, const char* glossary);
ARG_EXTERN struct arg_str* arg_str1(const char* shortopts, const char* longopts, const char* datatype, const char* glossary);
ARG_EXTERN struct arg_str* arg_strn(const char* shortopts, const char* longopts, const char* datatype, int mincount, int maxcount, const char* glossary);

ARG_EXTERN struct arg_rex* arg_rex0(const char* shortopts, const char* longopts, const char* pattern, const char* datatype, int flags, const char* glossary);
ARG_EXTERN struct arg_rex* arg_rex1(const char* shortopts, const char* longopts, const char* pattern, const char* datatype, int flags, const char* glossary);
ARG_EXTERN struct arg_rex* arg_rexn(const char* shortopts,
                         const char* longopts,
                         const char* pattern,
                         const char* datatype,
                         int mincount,
                         int maxcount,
                         int flags,
                         const char* glossary);

ARG_EXTERN struct arg_file* arg_file0(const char* shortopts, const char* longopts, const char* datatype, const char* glossary);
ARG_EXTERN struct arg_file* arg_file1(const char* shortopts, const char* longopts, const char* datatype, const char* glossary);
ARG_EXTERN struct arg_file* arg_filen(const char* shortopts, const char* longopts, const char* datatype, int mincount, int maxcount, const char* glossary);

ARG_EXTERN struct arg_date* arg_date0(const char* shortopts, const char* longopts, const char* format, const char* datatype, const char* glossary);
ARG_EXTERN struct arg_date* arg_date1(const char* shortopts, const char* longopts, const char* format, const char* datatype, const char* glossary);
ARG_EXTERN struct arg_date* arg_daten(const char* shortopts, const char* longopts, const char* format, const char* datatype, int mincount, int maxcount, const char* glossary);

ARG_EXTERN struct arg_end* arg_end(int maxcount);

#define ARG_DSTR_STATIC ((arg_dstr_freefn*)0)
#define ARG_DSTR_VOLATILE ((arg_dstr_freefn*)1)
#define ARG_DSTR_DYNAMIC ((arg_dstr_freefn*)3)

/**** other functions *******************************************/

/**
 * Checks the argument table for null entries.
 *
 * Each entry in the argument table is created by `arg_xxx` constructor
 * functions, such as `arg_litn`. These constructor functions will return NULL
 * when they fail to allocate enough memory. Instead of checking the return
 * value of each constructor function, we can make the code more readable by
 * calling `arg_nullcheck` when all the argument table entries have been
 * constructed:
 *
 * ```
 * struct arg_lit *list    = arg_lit0("lL",NULL,           "list files");
 * struct arg_lit *verbose = arg_lit0("v","verbose,debug", "verbose messages");
 * struct arg_lit *help    = arg_lit0(NULL,"help",         "print this help and exit");
 * struct arg_lit *version = arg_lit0(NULL,"version",      "print version and exit");
 * struct arg_end *end     = arg_end(20);
 * void *argtable[] = {list, verbose, help, version, end};
 * const char *progname = "myprog";
 * int exitcode = 0;
 *
 * if (arg_nullcheck(argtable) != 0)
 * {
 *     printf("%s: insufficient memory\n", progname);
 *     exitcode = 1;
 *     goto exit;
 * }
 * ```
 *
 * @param argtable An array of argument table structs.
 *
 * @return
 *   Returns 1 if any are found, zero otherwise.
 */
ARG_EXTERN int arg_nullcheck(void** argtable);

/**
 * Parses the command-line arguments.
 *
 * @param argc An integer representing the number of command-line arguments
 *   passed to the program. The *argc* parameter is always greater than or equal
 *   to 1.
 * @param argv An array of null-terminated strings representing the command-line
 *   arguments passed to the program. By convention, `argv[0]` is the command
 *   with which the program is invoked. `argv[1]` is the first command-line
 *   argument, and so on, until `argv[argc]`, which is always NULL.
 * @param argtable An array of argument table structs.
 *
 * @return Number of errors found.
 */
ARG_EXTERN int arg_parse(int argc, char** argv, void** argtable);

/**
 * @brief Mainly used in error handling functions.
 *
 * @param fp FILE descriptor
 * @param shortopts A pointer to a WNDCLASSEX structure. You must fill the
 *   structure with the appropriate class attributes before passing it to the
 *   function.
 * @param longopts The second one, which follows @p shortopts.
 * @param datatype The second one, which follows @p shortopts.
 * @param suffix The second one, which follows @p shortopts.
 */
ARG_EXTERN void arg_print_option(FILE* fp, const char* shortopts, const char* longopts, const char* datatype, const char* suffix);
ARG_EXTERN void arg_print_option_ds(arg_dstr_t ds, const char* shortopts, const char* longopts, const char* datatype, const char* suffix);

/**
 * @brief GNU-style command-line option syntax.
 *
 * @param fp FILE descriptor
 * @param argtable A pointer to a WNDCLASSEX structure. You must fill the
 *   structure with the appropriate class attributes before passing it to the
 *   function.
 * @param suffix The second one, which follows @p shortopts.
 */
ARG_EXTERN void arg_print_syntax(FILE* fp, void** argtable, const char* suffix);
ARG_EXTERN void arg_print_syntax_ds(arg_dstr_t ds, void** argtable, const char* suffix);

/**
 * @brief More verbose style command-line option syntax.
 *
 * @param fp FILE descriptor
 * @param argtable A pointer to a WNDCLASSEX structure. You must fill the
 *   structure with the appropriate class attributes before passing it to the
 *   function.
 * @param suffix The second one, which follows @p shortopts.
 */
ARG_EXTERN void arg_print_syntaxv(FILE* fp, void** argtable, const char* suffix);
ARG_EXTERN void arg_print_syntaxv_ds(arg_dstr_t ds, void** argtable, const char* suffix);

/**
 * @brief customizable glossary.
 *
 * @param fp FILE descriptor
 * @param argtable A pointer to a WNDCLASSEX structure. You must fill the
 *   structure with the appropriate class attributes before passing it to the
 *   function.
 * @param format Printing format.
 */
ARG_EXTERN void arg_print_glossary(FILE* fp, void** argtable, const char* format);
ARG_EXTERN void arg_print_glossary_ds(arg_dstr_t ds, void** argtable, const char* format);

/**
 * @brief GNU-style glossary.
 *
 * @param fp FILE descriptor
 * @param argtable A pointer to a WNDCLASSEX structure. You must fill the
 *   structure with the appropriate class attributes before passing it to the
 *   function.
 */
ARG_EXTERN void arg_print_glossary_gnu(FILE* fp, void** argtable);
ARG_EXTERN void arg_print_glossary_gnu_ds(arg_dstr_t ds, void** argtable);

ARG_EXTERN void arg_print_errors(FILE* fp, struct arg_end* end, const char* progname);
ARG_EXTERN void arg_print_errors_ds(arg_dstr_t ds, struct arg_end* end, const char* progname);

ARG_EXTERN void arg_print_formatted(FILE *fp, const unsigned lmargin, const unsigned rmargin, const char *text);


/**
 * Deallocates or frees non-null entries of the argument table.
 *
 * @param argtable An array of argument table structs.
 * @param n The number of structs in the argument table.
 */
ARG_EXTERN void arg_freetable(void** argtable, size_t n);

ARG_EXTERN arg_dstr_t arg_dstr_create(void);
ARG_EXTERN void arg_dstr_destroy(arg_dstr_t ds);
ARG_EXTERN void arg_dstr_reset(arg_dstr_t ds);
ARG_EXTERN void arg_dstr_free(arg_dstr_t ds);
ARG_EXTERN void arg_dstr_set(arg_dstr_t ds, char* str, arg_dstr_freefn* free_proc);
ARG_EXTERN void arg_dstr_cat(arg_dstr_t ds, const char* str);
ARG_EXTERN void arg_dstr_catc(arg_dstr_t ds, char c);
ARG_EXTERN void arg_dstr_catf(arg_dstr_t ds, const char* fmt, ...);
ARG_EXTERN char* arg_dstr_cstr(arg_dstr_t ds);

ARG_EXTERN void arg_cmd_init(void);
ARG_EXTERN void arg_cmd_uninit(void);
ARG_EXTERN void arg_cmd_register(const char* name, arg_cmdfn* proc, const char* description, void* ctx);
ARG_EXTERN void arg_cmd_unregister(const char* name);
ARG_EXTERN int arg_cmd_dispatch(const char* name, int argc, char* argv[], arg_dstr_t res);
ARG_EXTERN unsigned int arg_cmd_count(void);
ARG_EXTERN arg_cmd_info_t* arg_cmd_info(const char* name);
ARG_EXTERN arg_cmd_itr_t arg_cmd_itr_create(void);
ARG_EXTERN void arg_cmd_itr_destroy(arg_cmd_itr_t itr);
ARG_EXTERN int arg_cmd_itr_advance(arg_cmd_itr_t itr);
ARG_EXTERN char* arg_cmd_itr_key(arg_cmd_itr_t itr);
ARG_EXTERN arg_cmd_info_t* arg_cmd_itr_value(arg_cmd_itr_t itr);
ARG_EXTERN int arg_cmd_itr_search(arg_cmd_itr_t itr, void* k);
ARG_EXTERN void arg_mgsort(void* data, int size, int esize, int i, int k, arg_comparefn* comparefn);
ARG_EXTERN void arg_make_get_help_msg(arg_dstr_t res);
ARG_EXTERN void arg_make_help_msg(arg_dstr_t ds, const char* cmd_name, void** argtable);
ARG_EXTERN void arg_make_syntax_err_msg(arg_dstr_t ds, void** argtable, struct arg_end* end);
ARG_EXTERN int arg_make_syntax_err_help_msg(arg_dstr_t ds, const char* name, int help, int nerrors, void** argtable, struct arg_end* end, int* exitcode);
ARG_EXTERN void arg_set_module_name(const char* name);
ARG_EXTERN void arg_set_module_version(int major, int minor, int patch, const char* tag);

/**** deprecated functions, for back-compatibility only ********/

/**
 * arg_free() is deprecated in favour of arg_freetable() due to a flaw in its design.
 * The flaw results in memory leak in the (very rare) case that an intermediate
 * entry in the argtable array failed its memory allocation while others following
 * that entry were still allocated ok. Those subsequent allocations will not be
 * deallocated by arg_free().
 * Despite the unlikeliness of the problem occurring, and the even unlikelier event
 * that it has any deliterious effect, it is fixed regardless by replacing arg_free()
 * with the newer arg_freetable() function.
 * We still keep arg_free() for backwards compatibility.
 */
ARG_EXTERN void arg_free(void** argtable);

#ifdef __cplusplus
}
#endif
#endif
