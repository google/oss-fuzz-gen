//
//  main.c
//  CreateTableParser
//
//  Created by Marco Bambini on 14/02/16.
//

#include "sql3parse_table.h"
#include "sql3parse_debug.h"

int main (void) {
    const char *test[] = {
        // https://www.sqlite.org/lang_createtable.html
        
        "CREATE TABLE foo (col1 INTEGER PRIMARY KEY AUTOINCREMENT, col2 TEXT, col3 TEXT);",
        
        "CREATE TABLE t1(x INTEGER PRIMARY KEY, y);",
        
        "create table employee(first varchar(15),last varchar(20),age number(3),address varchar(30),city varchar(20),state varchar(20));",
        
        "CREATE TEMP TABLE IF NOT EXISTS main.foo /* This is the main table */ (col1 INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, col2 TEXT DEFAULT CURRENT_TIMESTAMP, col3 FLOAT(8.12), col4 BLOB COLLATE BINARY /* Use this column for storing pictures */, CONSTRAINT tbl1 UNIQUE (col1 COLLATE c1 ASC, col2 COLLATE c2 DESC)) WITHOUT ROWID; -- this is a line comment",
        
        "CREATE TABLE \"BalancesTbl2\" (\"id\" INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,  \"checkingBal\" REAL DEFAULT 0,  \"cashBal\" REAL DEFAULT .0,  \"defitCardBal\" REAL DEFAULT 1.0,  \"creditCardBal\" REAL DEFAULT +1.5,  testValue TEXT DEFAULT 'Hello World',   testValue2 TEXT DEFAULT 'Hello''s World', testValue3 TEXT DEFAULT \"Hello''s World\", testValue4 TEXT DEFAULT \"Hello\"\" World\") WITHOUT ROWID, STRICT;",
        
        "CREATE TABLE User\
            -- A table comment\n\
            (\
            uid INTEGER,    -- A field comment\n\
            flags INTEGER,  -- Another field comment\n\
            test TEXT /* Another C style comment */\
            );",
        
        "CREATE TABLE User\
            -- A table comment\n\
        (\
            uid INTEGER,    -- A field comment\n\
            flags /*This is another column comment*/ INTEGER   -- Another field comment\n\
        , test -- test 123\n\
        INTEGER, UNIQUE (flags /* Hello World*/, test) -- This is another table comment\n\
        );",
        
        // https://www.sqlite.org/lang_altertable.html
        
        "ALTER TABLE foo RENAME TO bar",
        
        "ALTER TABLE temp.foo RENAME TO bar",
        
        "ALTER TABLE foo RENAME COLUMN col1 TO col2",
        
        "ALTER TABLE foo RENAME col1 TO col2",
        
        "ALTER TABLE foo DROP COLUMN col1",
        
        "ALTER TABLE foo ADD COLUMN col1 TEXT DEFAULT 'Hello' COLLATE NOCASE",
        
        NULL
    };
    
    for (int i=0;;++i) {
        const char *sql = test[i];
        if (sql == NULL) break;
        
        sql3error_code err;
        printf("Parsing: %s\n\n", sql);
        sql3table *table = sql3parse_table(sql, 0, &err);
        if (!table) {
            printf("An error occurred while parsing table (%d).\n", err);
            return -1;
        }
        
        table_dump(table);
        sql3table_free(table);
    }
	
    return 0;
}
