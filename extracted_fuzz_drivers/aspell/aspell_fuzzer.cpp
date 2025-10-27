#include <algorithm>
#include <aspell.h>
#include <libgen.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

static int enable_diags;
static char data_dir[1024];

#define FUZZ_DEBUG(FMT, ...)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           \
  if (enable_diags) {                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  \
    fprintf(stderr, FMT, ##__VA_ARGS__);                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               \
    fprintf(stderr, "\n");                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             \
  }
static const size_t MAX_CONFIG_LEN = 10 * 1024;

int parse_config(AspellConfig *spell_config, uint8_t *config, size_t config_len);

// On startup, this function is called once. Use it to access argv.
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  char *argv0_copy = strdup((*argv)[0]);

  // Create the data dir.
  snprintf(data_dir, sizeof(data_dir), "%s/dict", dirname(argv0_copy));

  // Free off the temporary variable.
  free(argv0_copy);

  printf("Init: Running with data-dir: %s\n", data_dir);

  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  AspellCanHaveError *possible_err = NULL;
  AspellSpeller *spell_checker = NULL;
  AspellConfig *spell_config = NULL;
  AspellDocumentChecker *doc_checker = NULL;
  AspellCanHaveError *doc_err = NULL;
  AspellToken token;
  const char *data_str = reinterpret_cast<const char *>(data);
  uint8_t config[MAX_CONFIG_LEN];
  size_t config_len;
  int rc;

  // Enable or disable diagnostics based on the FUZZ_VERBOSE environment flag.
  enable_diags = (getenv("FUZZ_VERBOSE") != NULL);

  // Copy up to MAX_CONFIG_LEN bytes from the data.
  config_len = std::min(size, MAX_CONFIG_LEN);
  memcpy(config, data, config_len);

  // Create a new configuration class.
  spell_config = new_aspell_config();

  // Parse configuration. Exit if the configuration was bad.
  rc = parse_config(spell_config, config, config_len);
  if (rc == -1) {
    FUZZ_DEBUG("Configuration parsing failed");
    goto EXIT_LABEL;
  }

  // Move the data pointer past the config.
  data_str += rc;
  size -= rc;

  FUZZ_DEBUG("Document: %.*s", (int)size, data_str);

  // Replace the data dir with the relative directory so that it works wherever
  // it is run from, so long as dictionary files are installed relative to it.
  FUZZ_DEBUG("Overriding data-dir to %s", data_dir);
  aspell_config_replace(spell_config, "data-dir", data_dir);

  // Convert the configuration to a spell checker.
  possible_err = new_aspell_speller(spell_config);
  if (aspell_error_number(possible_err) != 0) {
    // Failed on configuration.
    FUZZ_DEBUG("Failed to create speller: %s", aspell_error_message(possible_err));
    delete_aspell_can_have_error(possible_err);
    goto EXIT_LABEL;
  }

  // Create a spell checker.
  spell_checker = to_aspell_speller(possible_err);

  // Convert the spell checker to a document checker.
  doc_err = new_aspell_document_checker(spell_checker);
  if (aspell_error(doc_err) != 0) {
    // Failed to convert to a document checker.
    FUZZ_DEBUG("Failed to create document checker: %s", aspell_error_message(doc_err));
    delete_aspell_can_have_error(doc_err);
    goto EXIT_LABEL;
  }

  doc_checker = to_aspell_document_checker(doc_err);

  // Process the remainder of the document.
  aspell_document_checker_process(doc_checker, data_str, size);

  // Iterate over all misspellings.
  token = aspell_document_checker_next_misspelling(doc_checker);

  FUZZ_DEBUG("Token len %d", token.len);

  for (; token.len != 0; token = aspell_document_checker_next_misspelling(doc_checker)) {
    // Get spelling suggestions for the misspelling.
    auto word_list = aspell_speller_suggest(spell_checker, data_str + token.offset, token.len);

    // Iterate over the suggested replacement words in the word list.
    AspellStringEnumeration *els = aspell_word_list_elements(word_list);

    for (const char *word = aspell_string_enumeration_next(els); word != 0; word = aspell_string_enumeration_next(els)) {
      // Conditionally print out the suggested replacement words.
      FUZZ_DEBUG("Suggesting replacement for word at offset %d len %d: %s", token.offset, token.len, word);
    }
    delete_aspell_string_enumeration(els);
  }

EXIT_LABEL:

  if (doc_checker != NULL) {
    delete_aspell_document_checker(doc_checker);
  }

  if (spell_checker != NULL) {
    delete_aspell_speller(spell_checker);
  }

  if (spell_config != NULL) {
    delete_aspell_config(spell_config);
  }

  return 0;
}

// Returns -1 on error, or the number of bytes consumed from the config string
// otherwise.
int parse_config(AspellConfig *spell_config, uint8_t *config, size_t config_len) {
  uint8_t line[MAX_CONFIG_LEN];

  uint8_t *config_ptr = config;
  size_t config_ptr_used = 0;

  uint8_t *delimiter;

  // Iterate over the lines.
  for (delimiter = (uint8_t *)memchr(config_ptr, '\n', config_len - config_ptr_used); delimiter != NULL; delimiter = (uint8_t *)memchr(config_ptr, '\n', config_len - config_ptr_used)) {
    int line_len = delimiter - config_ptr;

    if (line_len == 0) {
      // The line is zero-length; it's the end of configuration. Skip over the
      // delimiter and break out.
      FUZZ_DEBUG("Breaking out of config");
      config_ptr++;
      config_ptr_used++;
      break;
    }

    // Copy the line into the line array. Replace the newline by a null.
    memcpy(line, config_ptr, line_len);
    line[line_len] = 0;

    // Try and split the line by =.
    uint8_t *kv_delim = (uint8_t *)memchr(line, '=', line_len);

    if (kv_delim == NULL) {
      // Can't split as a k/v pair. Exit early.
      return -1;
    }

    // Convert the line into a key, value pair.
    kv_delim[0] = 0;

    char *keyword = reinterpret_cast<char *>(line);
    char *value = reinterpret_cast<char *>(kv_delim + 1);

    FUZZ_DEBUG("Key: %s; Value: %s", keyword, value);
    int ok = aspell_config_replace(spell_config, keyword, value);
    if (!ok) {
      // Log any errors and continue.
      FUZZ_DEBUG("Config error from aspell_config_replace: %s", aspell_config_error_message(spell_config));
    }

    // Advance the config pointers.  Make sure to add 1 for the delimiter.
    config_ptr += (line_len + 1);
    config_ptr_used += (line_len + 1);
  }

  // Return how much data  was used.
  FUZZ_DEBUG("Used %zu bytes of configuration data", config_ptr_used);

  return config_ptr_used;
}
