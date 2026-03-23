#include <criterion/criterion.h>
#include <criterion/logging.h>
#include <stdio.h>
#include <stdlib.h>

#define BINARY "./ipk-L4-scan"

// Helper function to run the command and get the exit code
int run_app(const char* args) {
    char command[512];
    // Redirect stderr to /dev/null if you only care about clean runs
    sprintf(command, "sudo %s %s > /dev/null 2>&1", BINARY, args);
    fprintf(stderr, "Running command: %s\n", command);
    return system(command);
}

Test(cli_logic, help_flag) {
    int status = run_app("-h");
    cr_assert_eq(status, 0, "Program should exit with 0 when -h is provided.");
}

Test(cli_logic, missing_interface) {
    int status = run_app("localhost");
    cr_assert_neq(status, 0, "Program should exit with non-zero when -i is missing.");
}