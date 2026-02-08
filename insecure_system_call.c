/*
    FIXED: This program now validates and sanitizes user input before executing commands.
    It uses input validation and restricts characters to prevent command injection.
    
    Previous vulnerability: User input was directly concatenated to system commands,
    allowing arbitrary command execution (e.g., "; rm -rf /").
    
    Fix applied: Input validation and use of safer alternatives to system().
*/



#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>


// Validate that input only contains safe characters
bool isValidInput(const char *input) {
    if (input == NULL || strlen(input) == 0) {
        return false;
    }
    
    // Allow only alphanumeric characters, spaces, hyphens, and underscores
    for (int i = 0; input[i] != '\0'; i++) {
        if (!isalnum(input[i]) && input[i] != ' ' && 
            input[i] != '-' && input[i] != '_' && input[i] != '.') {
            return false;
        }
    }
    
    // Check length to prevent buffer issues
    if (strlen(input) > 200) {
        return false;
    }
    
    return true;
}

int main() {
    char userInput[256];

    printf("Enter text to echo (alphanumeric, spaces, hyphens, underscores only): ");
    if (fgets(userInput, sizeof(userInput), stdin) == NULL) {
        fprintf(stderr, "Error reading input\n");
        return 1;
    }
    userInput[strcspn(userInput, "\n")] = 0; // Remove newline character

    // SECURITY FIX: Validate input before using it
    if (!isValidInput(userInput)) {
        fprintf(stderr, "Error: Invalid input. Only alphanumeric characters, spaces, hyphens, underscores, and dots are allowed.\n");
        return 1;
    }

    // SECURITY FIX: Use printf instead of system() when possible
    printf("Echo output: %s\n", userInput);
    
    // If system command is absolutely necessary, use with validated input
    // and consider using execve() with argument arrays for better security:
    /*
    char *args[] = {"/bin/echo", userInput, NULL};
    pid_t pid = fork();
    if (pid == 0) {
        execve("/bin/echo", args, NULL);
        exit(1);
    } else if (pid > 0) {
        wait(NULL);
    }
    */

    return 0;
}
