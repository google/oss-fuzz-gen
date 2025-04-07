//
//  sql3parse_debug.c
//
//  Created by Marco Bambini on 01/03/16.
//

#include "sql3parse_debug.h"

//MARK: Enum2String Code -

static const char *sql3conflict_clause_str (sql3conflict_clause clause) {
	switch (clause) {
		case SQL3CONFLICT_NONE: return "NONE";
		case SQL3CONFLICT_ROLLBACK: return "ROOLBACK";
		case SQL3CONFLICT_ABORT: return "ABORT";
		case SQL3CONFLICT_FAIL: return "FAIL";
		case SQL3CONFLICT_IGNORE: return "IGNORE";
		case SQL3CONFLICT_REPLACE: return "REPLACE";
	}
}

static const char *sql3fk_action_str (sql3fk_action clause) {
	switch (clause) {
		case SQL3FKACTION_NONE: return "NONE";
		case SQL3FKACTION_SETNULL: return "SETNULL";
		case SQL3FKACTION_SETDEFAULT: return "SETDEFAULT";
		case SQL3FKACTION_CASCADE: return "CASCADE";
		case SQL3FKACTION_RESTRICT: return "RESTRICT";
		case SQL3FKACTION_NOACTION: return "NOACTION";
	}
}

static const char *sql3fk_deftype_str (sql3fk_deftype clause) {
	switch (clause) {
		case SQL3DEFTYPE_NONE: return "NONE";
		case SQL3DEFTYPE_DEFERRABLE: return "DEFERRABLE";
		case SQL3DEFTYPE_DEFERRABLE_INITIALLY_DEFERRED: return "DEFERRABLE_INITIALLY_DEFERRED";
		case SQL3DEFTYPE_DEFERRABLE_INITIALLY_IMMEDIATE: return "DEFERRABLE_INITIALLY_IMMEDIATE";
		case SQL3DEFTYPE_NOTDEFERRABLE: return "NOTDEFERRABLE";
		case SQL3DEFTYPE_NOTDEFERRABLE_INITIALLY_DEFERRED: return "NOTDEFERRABLE_INITIALLY_DEFERRED";
		case SQL3DEFTYPE_NOTDEFERRABLE_INITIALLY_IMMEDIATE: return "NOTDEFERRABLE_INITIALLY_IMMEDIAT";
	}
}

static const char *sql3constraint_type_str (sql3constraint_type type) {
	switch (type) {
		case SQL3TABLECONSTRAINT_PRIMARYKEY: return "PRIMARYKEY";
		case SQL3TABLECONSTRAINT_UNIQUE: return "UNIQUE";
		case SQL3TABLECONSTRAINT_CHECK: return "CHECK";
		case SQL3TABLECONSTRAINT_FOREIGNKEY: return "FOREIGNKEY";
	}
}

//MARK: - Dump Code -

static void sql3string_dump (sql3string *ptr, const char *label) {
	if (!ptr) return;
	if (!label) label = "";
	
	size_t len;
	const char *s = sql3string_ptr(ptr, &len);
	if (!s) return;
	printf("%s: %.*s\n", label, (int)len, s);
}

static void sql3idxcolumn_dump (sql3idxcolumn *idxcolumn) {
	if (!idxcolumn) return;
	
	sql3string *ptr = sql3idxcolumn_name(idxcolumn);
	sql3string_dump(ptr, "Index Column Name");
	
	ptr = sql3idxcolumn_collate(idxcolumn);
	sql3string_dump(ptr, "Index Column Collate");
	
	sql3order_clause order = sql3idxcolumn_order(idxcolumn);
	if (order != SQL3ORDER_NONE)
		printf("Index Column Order: %s\n", (order == SQL3ORDER_ASC) ? "ASC" : "DESC");
}

static void sql3foreignkey_dump (sql3foreignkey *fk) {
	if (!fk) return;
	
	// Table name
	sql3string *ptr = sql3foreignkey_table(fk);
	sql3string_dump(ptr, "Foreign Key Table");
	
	// Columns
	size_t num_columns = sql3foreignkey_num_columns(fk);
	for (size_t i=0; i<num_columns; ++i) {
		ptr = sql3foreignkey_get_column(fk, i);
		sql3string_dump(ptr, "Foreign Key Column");
	}
	
	// Flags
	sql3fk_action action = sql3foreignkey_ondelete_action(fk);
	printf("Foreign Key On Delete Clause: %s\n", sql3fk_action_str(action));
	
	action = sql3foreignkey_onupdate_action(fk);
	printf("Foreign Key On Update Clause: %s\n", sql3fk_action_str(action));
	
	ptr = sql3foreignkey_match(fk);
	sql3string_dump(ptr, "Match Name");
	
	sql3fk_deftype deferrable = sql3foreignkey_deferrable(fk);
	printf("Foreign Key Deferrable Clause: %s\n", sql3fk_deftype_str(deferrable));
}

static void sql3column_dump (sql3column *column) {
	// column name
	sql3string *ptr = sql3column_name(column);
	sql3string_dump(ptr, "Column Name");
	
	// column type
	ptr = sql3column_type(column);
	sql3string_dump(ptr, "Column Type");
	
	// column length
	ptr = sql3column_length(column);
	sql3string_dump(ptr, "Column Length");
	
	// constraint name
	ptr = sql3column_constraint_name(column);
	sql3string_dump(ptr, "Constraint Name");
	
    // column comment
    ptr = sql3column_comment(column);
    if (ptr) sql3string_dump(ptr, "Column Comment");
    
	// flags
	printf("Primary Key: %d\n", sql3column_is_primarykey(column));
	printf("Autoincrement: %d\n", sql3column_is_autoincrement(column));
	printf("Not NULL: %d\n", sql3column_is_notnull(column));
	printf("Unique: %d\n", sql3column_is_unique(column));
	
	// enums
	sql3order_clause order = sql3column_pk_order(column);
	if (order != SQL3ORDER_NONE)
		printf("Primary Key Order: %s\n", (order == SQL3ORDER_ASC) ? "ASC" : "DESC");
	
	sql3conflict_clause clause = sql3column_pk_conflictclause(column);
	if (clause != SQL3CONFLICT_NONE)
		printf("Primary Key Conflict Cause: %s\n", sql3conflict_clause_str(clause));
	
	clause = sql3column_notnull_conflictclause(column);
	if (clause != SQL3CONFLICT_NONE)
		printf("Not NULL Conflict Cause: %s\n", sql3conflict_clause_str(clause));
	
	clause = sql3column_unique_conflictclause(column);
	if (clause != SQL3CONFLICT_NONE)
		printf("Unique Conflict Cause: %s\n", sql3conflict_clause_str(clause));
	
	// check expr
	ptr = sql3column_check_expr(column);
	sql3string_dump(ptr, "Check Expression");
	
	// default expr
	ptr = sql3column_default_expr(column);
	sql3string_dump(ptr, "Default Expression");
	
	// collate name
	ptr = sql3column_collate_name(column);
	sql3string_dump(ptr, "Collate");
	
	// foreign key
	sql3foreignkey *fk = sql3column_foreignkey_clause(column);
	sql3foreignkey_dump(fk);
}

static void sql3tableconstraint_dump (sql3tableconstraint *constraint) {
	// constraint type
	sql3constraint_type type = sql3table_constraint_type(constraint);
	printf("Constraint Type: %s\n", sql3constraint_type_str(type));
	
	sql3string *ptr = sql3table_constraint_name(constraint);
	sql3string_dump(ptr, "Constraint Name");
	
	if ((type == SQL3TABLECONSTRAINT_PRIMARYKEY) || (type == SQL3TABLECONSTRAINT_UNIQUE)) {
		// indexed columns
		size_t num_idx = sql3table_constraint_num_idxcolumns(constraint);
		if (num_idx) {
			printf("Num Indexed Columns: %zu\n", num_idx);
			for (size_t i=0; i<num_idx; ++i) {
				sql3idxcolumn *idxcolumn = sql3table_constraint_get_idxcolumn(constraint, i);
				printf("\n== IDX COLUMN %zu ==\n", i);
				sql3idxcolumn_dump(idxcolumn);
			}
		}
		
		// conflict clause
		sql3conflict_clause clause = sql3table_constraint_conflict_clause(constraint);
		if (clause != SQL3CONFLICT_NONE)
			printf("Conflict Cause: %s\n", sql3conflict_clause_str(clause));
		return;
	}
	
	if (type == SQL3TABLECONSTRAINT_CHECK) {
		ptr = sql3table_constraint_check_expr(constraint);
		sql3string_dump(ptr, "Check Expr");
		return;
	}
	
	if (type == SQL3TABLECONSTRAINT_FOREIGNKEY) {
		// foreign key columns
		size_t num_fk = sql3table_constraint_num_fkcolumns(constraint);
		for (size_t i=0; i<num_fk; ++i) {
			ptr = sql3table_constraint_get_fkcolumn(constraint, i);
			sql3string_dump(ptr, "Foreign Key Column");
		}
		
		// foreign key clause
		sql3foreignkey *fk = sql3table_constraint_foreignkey_clause (constraint);
		sql3foreignkey_dump(fk);
	}
}

//MARK: -

static void table_dump_common (sql3table *table) {
    // schema name
    sql3string *ptr = sql3table_schema(table);
    sql3string_dump(ptr, "Schema Name");
    
    // table name
    ptr = sql3table_name(table);
    sql3string_dump(ptr, "Table Name");
    
    // table comment
    ptr = sql3table_comment(table);
    if (ptr) sql3string_dump(ptr, "Table Comment");
}

static void table_dump_create (sql3table *table) {
    printf("CREATE TABLE statement\n\n");
    
    // name
    table_dump_common(table);
    
    // flags
    printf("Temporary: %d\n", sql3table_is_temporary(table));
    printf("If Not Exists: %d\n", sql3table_is_ifnotexists(table));
    printf("Without RowID: %d\n", sql3table_is_withoutrowid(table));
    printf("Strict: %d\n", sql3table_is_strict(table));
    
    // columns
    size_t num_columns = sql3table_num_columns(table);
    printf("Num Columns: %zu\n", num_columns);
    for (size_t i=0; i<num_columns; ++i) {
        sql3column *column = sql3table_get_column(table, i);
        printf("\n== COLUMN %zu ==\n", i);
        sql3column_dump(column);
    }
    
    // table constraints
    size_t num_constraint = sql3table_num_constraints(table);
    printf("\nNum Table Constraint: %zu\n", num_constraint);
    for (size_t i=0; i<num_constraint; ++i) {
        sql3tableconstraint *constraint = sql3table_get_constraint(table, i);
        printf("\n== TABLE CONSTRAINT %zu ==\n", i);
        sql3tableconstraint_dump(constraint);
    }
}

static void table_dump_alter (sql3table *table) {
    sql3statement_type type = sql3table_type(table);
    
    if (type == SQL3ALTER_RENAME_TABLE) {
        printf("ALTER TABLE RENAME TABLE statement\n\n");
        table_dump_common(table);
        
        sql3string *ptr = sql3table_new_name(table);
        sql3string_dump(ptr, "New Table Name");
        return;
    }
    
    if (type == SQL3ALTER_RENAME_COLUMN) {
        printf("ALTER TABLE RENAME COLUMN statement\n\n");
        table_dump_common(table);
        
        sql3string *ptr = sql3table_current_name(table);
        sql3string_dump(ptr, "Column Name");
        ptr = sql3table_new_name(table);
        sql3string_dump(ptr, "New Column Name");
        return;
    }
    
    if (type == SQL3ALTER_DROP_COLUMN) {
        printf("ALTER TABLE DROP COLUMN statement\n\n");
        table_dump_common(table);
        
        sql3string *ptr = sql3table_current_name(table);
        sql3string_dump(ptr, "Column Name");
        return;
    }
    
    if (type == SQL3ALTER_ADD_COLUMN) {
        printf("ALTER TABLE ADD COLUMN statement\n\n");
        table_dump_common(table);
        
        // only ONE column in the ALTER TABLE ADD COLUMN statement
        sql3column *column = sql3table_get_column(table, 0);
        sql3column_dump(column);
        
        return;
    }
}

//MARK: - Public -

void table_dump (sql3table *table) {
	if (!table) return;
	
    // sanity check
    sql3statement_type type = sql3table_type(table);
    if (type == SQL3CREATE_UNKNOWN) {
        printf("Unknown statement type.\n");
        return;
    }
    
    // dump create/alter table details
    (type == SQL3CREATE_TABLE) ? table_dump_create(table) : table_dump_alter(table);
    
    printf("\n");
}
