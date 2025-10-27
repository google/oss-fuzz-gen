#include "runner.h"
#include <bnfuzz/module_cxx.h>
#include <stdint.h>
#include <stdlib.h>

#include "declare_modules.h"

bool g_logging, g_no_negative, g_no_compare, g_all_operations, g_swapswapop;
Runner *g_runner = NULL;

size_t num_len;
size_t operation;
size_t num_loops;

static void print_help(void) {
  printf("\n");
  printf("Bignum fuzzer by Guido Vranken -- https://github.com/guidovranken/bignum-fuzzer\n");
  printf("\n");
  printf("Valid command-line parameters:\n");
  printf("\n");
  printf("\t--logging : print input bignums, operation # and output bignums\n");
  printf("\t--no_negative : interpret all input bignums as positive integers \n");
  printf("\t--no_compare : disable differential fuzzing; don't compare output bignums across modules\n");
  printf("\t--num_len=<n>: input bignum size in number of decimal digits\n");
  printf("\t--operation=<n> : disregard operation encoded in input; run each iteration with this operation\n");
  printf("\t--num_loops : maximum # of operations to execute\n");
  printf("\t--all_operations : disregard operation encoded in input; run each iteration with all operations\n");
  printf("\t--swapswapop : swap bignums 2 times, then run operation\n");
  printf("\n");
  exit(0);
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  int i;
  char **_argv = *argv;

  g_logging = false;
  g_no_negative = false;
  g_no_compare = false;
  g_all_operations = false;
  g_swapswapop = false;
  num_len = 0;
  operation = 0;
  num_loops = 2;

  for (i = 0; i < *argc; i++) {
    if (!strcmp(_argv[i], "--logging")) {
      g_logging = true;
    } else if (!strcmp(_argv[i], "--no_negative")) {
      g_no_negative = true;
    } else if (!strcmp(_argv[i], "--no_compare")) {
      g_no_compare = true;
    } else if (!strncmp(_argv[i], "--num_len=", 10)) {
      long l;
      l = strtol(_argv[i] + 10, NULL, 10);
      if (l < 1) {
        printf("Invalid --num_len argument\n");
        print_help();
      }
      num_len = (size_t)l;

    } else if (!strncmp(_argv[i], "--operation=", 12)) {
      long l;
      l = strtol(_argv[i] + 12, NULL, 10);
      if (l < 1) {
        printf("Invalid --operation argument\n");
        print_help();
      }
      operation = (size_t)l;

    } else if (!strncmp(_argv[i], "--num_loops=", 12)) {
      long l;
      l = strtol(_argv[i] + 12, NULL, 10);
      if (l < 0) {
        printf("Invalid --num_loops argument\n");
        print_help();
      }
      num_loops = (size_t)l;

    } else if (!strcmp(_argv[i], "--all_operations")) {
      g_all_operations = true;
    } else if (!strcmp(_argv[i], "--swapswapop")) {
      g_swapswapop = true;
    } else if (!strcmp(_argv[i], "--help")) {
      print_help();
    } else {
      if (_argv[i][0] == '-' && _argv[i][1] == '-') {
        printf("Invalid option: %s\n", _argv[i]);
        print_help();
      }
    }
  }

  if (g_all_operations == true && operation != 0) {
    printf("You cannot specify --operation and --all_operations at the same time\n");
    print_help();
  }

#ifdef BNFUZZ_FLAG_NO_NEGATIVE
  g_no_negative = true;
#endif

#ifdef BNFUZZ_FLAG_NO_COMPARE
  g_no_compare = true;
#endif

#ifdef BNFUZZ_FLAG_NUM_LEN
  num_len = BNFUZZ_FLAG_NUM_LEN;
#endif

#ifdef BNFUZZ_FLAG_OPERATION
  operation = BNFUZZ_FLAG_OPERATION;
#endif

#ifdef BNFUZZ_FLAG_NUM_LOOPS
  num_loops = BNFUZZ_FLAG_NUM_LOOPS;
#endif

#ifdef BNFUZZ_FLAG_ALL_OPERATIONS
  g_all_operations = true;
#endif

#ifdef BNFUZZ_FLAG_SWAPSWAPOP
  g_swapswapop = true;
#endif

  module_container_t modules;

#include "push_modules.h"

  g_runner = new Runner(modules);

  if (g_logging == true) {
    g_runner->SetLogging(true);
  }
  if (g_no_negative == true) {
    g_runner->SetNegative(false);
  }
  if (modules.size() < 2 || g_no_compare == true) {
    g_runner->SetCompare(false);
  }
  if (g_swapswapop == true) {
    g_runner->SetSwapSwapOp(true);
  }
  if (num_len != 0) {
    g_runner->SetNumberLength(num_len);
  }
  g_runner->SetNumLoops(num_loops);

  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  Input input(data, size);

  if (g_all_operations == true) {
    for (int i = 0; i < BN_FUZZ_OP_LAST; i++) {
      g_runner->SetOperation(i == 0 ? BN_FUZZ_OP_NOP : (operation_t)i);
      g_runner->run(input);
      input.rewind();
    }
  } else {
    g_runner->SetOperation(operation);
    g_runner->run(input);
  }

  return 0;
}
