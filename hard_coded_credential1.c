/*
    FIXED: This program now uses environment variables for sensitive credentials
    instead of hardcoding them in source code.
    
    Previous vulnerability: Password "secret123" was hardcoded in source code,
    exposing it to anyone with repository access.
    
    Fix applied: Use environment variables for credentials.
    
    Usage: Set environment variable before running:
    export APP_PASSWORD="your_secure_password"
    ./hard_coded_credential1
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    char inputPassword[50];
    
    // SECURITY FIX: Get password from environment variable instead of hardcoding
    const char *expectedPassword = getenv("APP_PASSWORD");
    
    if (expectedPassword == NULL || strlen(expectedPassword) == 0) {
        fprintf(stderr, "Error: APP_PASSWORD environment variable not set.\n");
        fprintf(stderr, "Please set it using: export APP_PASSWORD=\"your_password\"\n");
        return 1;
    }

    printf("Enter password to access the system file: ");
    if (fgets(inputPassword, sizeof(inputPassword), stdin) == NULL) {
        fprintf(stderr, "Error reading input\n");
        return 1;
    }
    inputPassword[strcspn(inputPassword, "\n")] = 0; // Remove newline character

    if (strcmp(inputPassword, expectedPassword) == 0) {
        printf("Access granted. Reading system file...\n");

        // Attempting to read a system-critical file (with a fake filename)
        const char *criticalFilePath = "/etc/fake_critical_file.conf";
        FILE *file = fopen(criticalFilePath, "r");

        if (file == NULL) {
            perror("Error opening file");
        } else {
            // Read and print the contents of the file (hypothetical)
            char buffer[256];
            while (fgets(buffer, sizeof(buffer), file) != NULL) {
                printf("%s", buffer);
            }
            fclose(file);
        }
    } else {
        printf("Access denied.\n");
    }

    return 0;
}
