/*
    FIXED VERSION: SQL Injection Vulnerability Remediated
    
    This program demonstrates the SECURE way to handle user input in SQL queries.
    It uses parameterized queries (prepared statements) to prevent SQL injection.
    
    Key Changes:
    - Replaced direct sqlite3_exec() with prepared statements
    - Used sqlite3_prepare_v2() and sqlite3_bind_*() functions
    - Added input validation and sanitization
    - Whitelisted allowed operations
    
    Original vulnerability: CWE-89 (SQL Injection)
    Remediation: Parameterized queries with input validation
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <ctype.h>

/*
    This callback function is tailor made for what SQLite expects.
*/
int callback(void *data, int argc, char **argv, char **azColName) {
    int *count = (int*)data;
    *count = atoi(argv[0]);
    return 0;
}

/*
    Secure function to insert a user using prepared statements
    This prevents SQL injection by using parameterized queries
*/
int secure_insert_user(sqlite3 *db, int id, const char *name) {
    sqlite3_stmt *stmt;
    int rc;
    
    // Prepare the SQL statement with placeholders
    const char *sql = "INSERT INTO Users(Id, Name) VALUES(?, ?);";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return rc;
    }
    
    // Bind the parameters (this prevents injection)
    sqlite3_bind_int(stmt, 1, id);
    sqlite3_bind_text(stmt, 2, name, -1, SQLITE_TRANSIENT);
    
    // Execute the statement
    rc = sqlite3_step(stmt);
    
    // Clean up
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Execution failed: %s\n", sqlite3_errmsg(db));
        return rc;
    }
    
    printf("User inserted successfully: ID=%d, Name=%s\n", id, name);
    return SQLITE_OK;
}

/*
    Secure function to query users by name using prepared statements
*/
int secure_query_user(sqlite3 *db, const char *name) {
    sqlite3_stmt *stmt;
    int rc;
    
    // Prepare the SQL statement with placeholders
    const char *sql = "SELECT Id, Name FROM Users WHERE Name = ?;";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return rc;
    }
    
    // Bind the parameter
    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);
    
    // Execute and fetch results
    printf("\nQuery Results:\n");
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        int id = sqlite3_column_int(stmt, 0);
        const unsigned char *user_name = sqlite3_column_text(stmt, 1);
        printf("ID: %d, Name: %s\n", id, user_name);
    }
    
    sqlite3_finalize(stmt);
    return SQLITE_OK;
}

/*
    Input validation function - sanitize and validate user input
*/
int validate_name(const char *name) {
    if (name == NULL || strlen(name) == 0) {
        return 0;
    }
    
    // Check length (max 100 characters)
    if (strlen(name) > 100) {
        fprintf(stderr, "Error: Name too long (max 100 characters)\n");
        return 0;
    }
    
    // Allow only alphanumeric characters, spaces, and basic punctuation
    for (int i = 0; name[i] != '\0'; i++) {
        if (!isalnum(name[i]) && name[i] != ' ' && name[i] != '-' && name[i] != '_') {
            fprintf(stderr, "Error: Name contains invalid characters\n");
            return 0;
        }
    }
    
    return 1;
}


int main() {
    sqlite3 *db;
    char *err_msg = 0;
    int rc;

    // Create a table and insert one row. For simplicity, error handling is minimal.
    
    // Open an in-memory SQLite database
    rc = sqlite3_open(":memory:", &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        return 1;
    }
    
    // Create a dummy table
    char *sql = "CREATE TABLE Users(Id INT, Name TEXT);";
    rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return 1;
    }
    
    // Insert initial row using prepared statement
    secure_insert_user(db, 1, "Alice");
    
    // Print row count in USERS
    int rowCount = 0;
    sql = "SELECT COUNT(*) FROM Users;";
    rc = sqlite3_exec(db, sql, callback, &rowCount, &err_msg);
    printf("Current number of users: %d\n", rowCount);


    // SECURE USER INPUT HANDLING
    printf("\n=== Secure User Input Demo ===\n");
    printf("Choose an operation:\n");
    printf("1. Insert a new user\n");
    printf("2. Query user by name\n");
    printf("Enter choice (1 or 2): ");
    
    int choice;
    if (scanf("%d", &choice) != 1) {
        fprintf(stderr, "Invalid input\n");
        sqlite3_close(db);
        return 1;
    }
    getchar(); // Consume newline
    
    if (choice == 1) {
        // Secure insert operation
        int user_id;
        char user_name[256];
        
        printf("Enter user ID (integer): ");
        if (scanf("%d", &user_id) != 1) {
            fprintf(stderr, "Invalid ID\n");
            sqlite3_close(db);
            return 1;
        }
        getchar(); // Consume newline
        
        printf("Enter user name: ");
        fgets(user_name, 256, stdin);
        user_name[strcspn(user_name, "\n")] = 0; // Remove newline
        
        // Validate input before processing
        if (validate_name(user_name)) {
            secure_insert_user(db, user_id, user_name);
        } else {
            fprintf(stderr, "Invalid name. Operation cancelled.\n");
        }
        
    } else if (choice == 2) {
        // Secure query operation
        char search_name[256];
        
        printf("Enter name to search: ");
        fgets(search_name, 256, stdin);
        search_name[strcspn(search_name, "\n")] = 0; // Remove newline
        
        // Validate input before processing
        if (validate_name(search_name)) {
            secure_query_user(db, search_name);
        } else {
            fprintf(stderr, "Invalid name. Operation cancelled.\n");
        }
        
    } else {
        fprintf(stderr, "Invalid choice\n");
    }
    
    // Final row count
    rowCount = 0;
    sql = "SELECT COUNT(*) FROM Users;";
    rc = sqlite3_exec(db, sql, callback, &rowCount, &err_msg);
    printf("\nFinal number of users: %d\n", rowCount);
    
    // Verify table still exists (it should!)
    if (sqlite3_table_column_metadata(db, NULL, "Users", NULL, NULL, NULL, NULL, NULL, NULL) == SQLITE_OK) {
        printf("✓ Table 'Users' is still intact - SQL injection prevented!\n");
    }

    sqlite3_close(db);
    return 0;
}
