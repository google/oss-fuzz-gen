# State Machine Archetype

## Pattern Signature
```
init() → configure() → parse() → clean() → finalize() → cleanup()
```

## Characteristics
- Strict multi-step sequence
- Each step depends on previous
- State progresses through defined stages
- Invalid sequence causes crashes

## Typical APIs
- HTML/XML cleaners (tidy-html5)
- Document processors
- Compiler frontends
- Protocol handlers

## Preconditions
1. Functions called in exact order
2. Each step succeeds before next
3. Configuration before processing
4. Finalization before cleanup

## Postconditions
1. Each step returns status
2. State transitions on success
3. Error stops progression
4. Cleanup always possible

## Driver Pattern
```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < MIN_SIZE) return 0;
  
  // Step 1: Initialize
  TidyDoc doc = tidyCreate();
  if (!doc) return 0;
  
  // Step 2: Configure
  TidyBuffer err_buf;
  tidyBufInit(&err_buf);
  if (tidySetErrorBuffer(doc, &err_buf) < 0) goto cleanup;
  
  tidyOptSetBool(doc, TidyXhtmlOut, yes);
  
  // Step 3: Parse
  TidyBuffer input_buf;
  tidyBufAttach(&input_buf, (byte*)data, size);
  if (tidyParseBuffer(doc, &input_buf) < 0) goto cleanup;
  
  // Step 4: Process
  if (tidyCleanAndRepair(doc) < 0) goto cleanup;
  
  // Step 5: Finalize
  if (tidyRunDiagnostics(doc) < 0) goto cleanup;
  
  // Step 6: Output (optional)
  TidyBuffer output_buf;
  tidyBufInit(&output_buf);
  tidySaveBuffer(doc, &output_buf);
  tidyBufFree(&output_buf);
  
cleanup:
  tidyBufFree(&err_buf);
  tidyBufDetach(&input_buf);
  tidyRelease(doc);
  return 0;
}
```

## Parameter Strategy
- Document handle: FIX (from init)
- Configuration: FIX (standard safe config)
- Input data: DIRECT_FUZZ
- Options: CONSTRAIN (limited set)

## State Transitions
```
UNINITIALIZED
  → init() →
CREATED
  → configure() →
CONFIGURED
  → parse() →
PARSED
  → process() →
PROCESSED
  → finalize() →
FINALIZED
  → cleanup() →
DESTROYED
```

## Common Pitfalls
- Skipping configuration step
- Calling steps out of order
- Not checking intermediate returns
- Cleanup without proper state
- Re-entering a step

## Error Handling Strategy
```c
// Check each step
if (step1() < 0) goto cleanup;
if (step2() < 0) goto cleanup;
if (step3() < 0) goto cleanup;

// Cleanup works from any state
cleanup:
  safe_cleanup();  // Handles partial initialization
```

## Real Examples
- tidy-html5: Multi-step HTML cleaning
- libxml2: Pull parser with state machine
- Compiler passes: lex → parse → analyze → codegen

## Reference
See FUZZER_COOKBOOK.md Scenario 8

