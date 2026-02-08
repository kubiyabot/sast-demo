/*
    FIXED: This program now uses parameterized queries (prepared statements)
    to prevent SQL injection attacks. User input is safely bound to the query
    using sqlite3_bind_text, which prevents arbitrary SQL execution.
    
    Previous vulnerability: Direct execution of user input allowed SQL injection.
    Fix applied: Using prepared statements with parameter binding.
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

/*
    This callback function is tailor made for what SQLite expects.
*/
int callback(void *data, int argc, char **argv, char **azColName) {
    int *count = (int*)data;
    *count = atoi(argv[0]);
    return 0;
}


int main() {
    sqlite3 *db;
    char *err_msg = 0;
    int rc;

// Create a table and insert one row. For simplicity, error handling is sloopy.

    // Open an in-memory SQLite database
    rc = sqlite3_open(":memory:", &db);
    // Create a dummy table and insert a row
    char *sql = "CREATE TABLE Users(Id INT, Name TEXT);";
    rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    // Insert one row
    sql = "INSERT INTO Users(Id, Name) VALUES(1, 'Alice')";
    rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    // Print row number in USERS
    int rowCount = 0;
    sql = "SELECT COUNT(*) FROM Users;";
    rc = sqlite3_exec(db, sql, callback, &rowCount, &err_msg);
    // very basic error handling, not advisible in production code.
    if (rowCount !=1) exit(1);     



// FIXED: Now uses parameterized queries to prevent SQL injection
    char user_name[256];
    int user_id;
    printf("Enter user ID to insert: ");
    if (scanf("%d", &user_id) != 1) {
        fprintf(stderr, "Invalid input\n");
        sqlite3_close(db);
        return 1;
    }
    getchar(); // Consume newline
    
    printf("Enter user name: ");
    fgets(user_name, 256, stdin);
    user_name[strcspn(user_name, "\n")] = 0; // Remove newline character
    
    // Use prepared statements with parameter binding (SECURE)
    sqlite3_stmt *stmt;
    const char *safe_sql = "INSERT INTO Users(Id, Name) VALUES(?, ?)";
    
    rc = sqlite3_prepare_v2(db, safe_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 1;
    }
    
    // Bind parameters safely (prevents SQL injection)
    sqlite3_bind_int(stmt, 1, user_id);
    sqlite3_bind_text(stmt, 2, user_name, -1, SQLITE_STATIC);
    
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Execution failed: %s\n", sqlite3_errmsg(db));
    } else {
        printf("User inserted successfully using parameterized query\n");
    }
    
    sqlite3_finalize(stmt);

// Verify the insertion worked
    rowCount = 0;
    sql = "SELECT COUNT(*) FROM Users;";
    rc = sqlite3_exec(db, sql, callback, &rowCount, &err_msg);
    printf("Total users in table: %d\n", rowCount);

    sqlite3_close(db);
    return 0;
}
