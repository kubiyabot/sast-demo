/*
    FIXED: This program now uses proper format specifiers with printf.
    
    Previous vulnerability: User input was passed directly as format string,
    allowing attackers to read/write memory using format specifiers like %x, %n, %s.
    
    Fix applied: Always use explicit format specifier ("%s") when printing user input.
*/
#include <stdio.h>

int main() {
    char buf[100];
    
    printf("Enter a string: ");
    if (scanf("%99s", buf) != 1) {
        fprintf(stderr, "Error reading input\n");
        return 1;
    }
    
    // SECURITY FIX: Use explicit format specifier to prevent format string attacks
    printf("%s\n", buf); // SECURE: Format specifier protects against injection
    
    // Previously vulnerable code:
    // printf(buf); // DANGEROUS: User could inject %x, %n, %s, etc.
    
    return 0;
}
