/*
    FIXED: This program now uses fgets() instead of the deprecated gets().
    
    Previous vulnerability: gets() has no bounds checking and was removed from C11.
    It always causes buffer overflow vulnerabilities.
    
    Fix applied: Replace gets() with fgets() which includes buffer size checking.
*/
#include <stdio.h>
#include <string.h>

int main() {
    char buffer[50];

    printf("Enter a string: ");
    
    // SECURITY FIX: Use fgets() instead of gets()
    if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
        fprintf(stderr, "Error reading input\n");
        return 1;
    }
    
    // Remove trailing newline character if present
    buffer[strcspn(buffer, "\n")] = '\0';
    
    printf("You entered: %s\n", buffer);
    
    // Previously vulnerable code:
    // gets(buffer); // DANGEROUS: No bounds checking, removed from C11
    
    return 0;
}
