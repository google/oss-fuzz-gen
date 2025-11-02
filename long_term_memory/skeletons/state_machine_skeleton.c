// State Machine Pattern: init → configure → process → finalize → cleanup

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < MIN_SIZE) return 0;
  
  // Step 1: Initialize
  DOC_TYPE *doc = DOC_INIT();
  if (!doc) return 0;
  
  // Step 2: Configure
  BUFFER_TYPE err_buf;
  BUFFER_INIT(&err_buf);
  
  if (SET_ERROR_BUFFER(doc, &err_buf) < 0) goto cleanup;
  SET_OPTION(doc, OPTION_NAME, value);
  
  // Step 3: Parse/Load
  BUFFER_TYPE input_buf;
  BUFFER_ATTACH(&input_buf, data, size);
  
  if (PARSE(doc, &input_buf) < 0) goto cleanup;
  
  // Step 4: Process
  if (PROCESS(doc) < 0) goto cleanup;
  
  // Step 5: Finalize
  if (FINALIZE(doc) < 0) goto cleanup;
  
  // Step 6: Get output (optional)
  BUFFER_TYPE output_buf;
  BUFFER_INIT(&output_buf);
  SAVE(doc, &output_buf);
  BUFFER_FREE(&output_buf);
  
  // Cleanup (reverse order)
cleanup:
  BUFFER_FREE(&err_buf);
  BUFFER_DETACH(&input_buf);
  DOC_RELEASE(doc);
  return 0;
}
