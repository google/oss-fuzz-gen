#include "Processors/Executors/PullingPipelineExecutor.h"
#include <Interpreters/Context.h>
#include <Interpreters/executeQuery.h>
#include <Interpreters/registerInterpreters.h>

#include <AggregateFunctions/registerAggregateFunctions.h>
#include <Databases/registerDatabases.h>
#include <Dictionaries/registerDictionaries.h>
#include <Disks/registerDisks.h>
#include <Formats/registerFormats.h>
#include <Functions/registerFunctions.h>
#include <Storages/registerStorages.h>
#include <TableFunctions/registerTableFunctions.h>

using namespace DB;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  try {
    std::string input = std::string(reinterpret_cast<const char *>(data), size);

    static SharedContextHolder shared_context;
    static ContextMutablePtr context;

    auto initialize = [&]() mutable {
      if (context)
        return true;

      shared_context = Context::createShared();
      context = Context::createGlobal(shared_context.get());
      context->makeGlobalContext();
      context->setApplicationType(Context::ApplicationType::LOCAL);

      registerInterpreters();
      registerFunctions();
      registerAggregateFunctions();
      registerTableFunctions();
      registerDatabases();
      registerStorages();
      registerDictionaries();
      registerDisks(/* global_skip_access_check= */ true);
      registerFormats();

      return true;
    };

    static bool initialized = initialize();
    (void)initialized;

    auto io = DB::executeQuery(input, context, QueryFlags{.internal = true}, QueryProcessingStage::Complete).second;

    PullingPipelineExecutor executor(io.pipeline);
    Block res;
    while (!res && executor.pull(res))
      ;
  } catch (...) {
  }

  return 0;
}
