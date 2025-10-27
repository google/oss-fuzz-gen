#include "mdbtools.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  MdbHandle *mdb = mdb_open_buffer((void *)Data, Size, MDB_NOFLAGS);
  if (mdb) {
    mdb_read_catalog(mdb, MDB_TABLE);
    for (int j = 0; j < mdb->num_catalog; j++) {
      MdbCatalogEntry *entry = g_ptr_array_index(mdb->catalog, j);
      MdbTableDef *table = mdb_read_table(entry);
      if (table) {
        mdb_read_columns(table);
        mdb_rewind_table(table);
        while (mdb_fetch_row(table))
          ;
        mdb_free_tabledef(table);
      }
    }
    mdb_close(mdb);
  }
  return 0;
}
