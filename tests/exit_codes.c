/**
 * This file is part of the IPK Project 1 - OMEGA: L4 Scanner.
 * // 23.3. 2026 IPK 2026, FIT VUT Brno
 *  Author: Kristian Rucek > xrucekk00
 */

#include <criterion/criterion.h>
#include <criterion/logging.h>
#include <sysexits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

#define BINARY "./ipk-L4-scan"
#define CLR_RESET  "\x1b[0m"
#define CLR_CYAN   "\x1b[36m"
#define CLR_YELLOW "\x1b[33m"

char detected_iface[32] = {0};

// This setup interface was build with AI assitance
void suite_setup(void) {
    FILE *fp = popen(BINARY " -i | grep -v 'lo' | head -n 1", "r");
    if (!fp || fscanf(fp, "%31s", detected_iface) != 1) strcpy(detected_iface, "eth0");
    if (fp) pclose(fp);
    cr_log_info(CLR_CYAN "Detected active interface: %s" CLR_RESET, detected_iface);
}

TestSuite(cli_logic, .init = suite_setup);

int run_app(const char* args) {
    char processed[512], command[1024];
    char *placeholder = strstr(args, "IFACE");
    if (placeholder) {
        size_t prefix_len = placeholder - args;
        sprintf(processed, "%.*s%s%s", (int)prefix_len, args, detected_iface, placeholder + 5);
    } else {
        strcpy(processed, args);
    }
    snprintf(command, sizeof(command), "sudo " BINARY " %s > /dev/null 2>&1", processed);
    int raw_status = system(command);
    int exit_code = WEXITSTATUS(raw_status);
    fprintf(stderr, CLR_YELLOW "[EXEC] " CLR_RESET "%s (Exit: %d)\n", command, exit_code);
    return exit_code; 
}

/* ==========================================================================
   GROUPED TEST CATEGORIES
   ========================================================================== */

Test(cli_logic, help_and_information) {
    cr_assert_eq(run_app("-h"), EX_OK);
    cr_assert_eq(run_app("--help"), EX_OK);
    cr_assert_eq(run_app("-i"), EX_OK, "Interface listing should return EX_OK");
    cr_assert_eq(run_app("-h -i IFACE -t 80 localhost"), EX_OK, "Help overrides all");
    cr_assert_eq(run_app("-h --help"), EX_OK, "Multiple help flags");
}

Test(cli_logic, missing_mandatory_args) {
    cr_assert_eq(run_app(""), EX_USAGE, "No args");
    cr_assert_eq(run_app("-i IFACE"), EX_USAGE, "Only interface");
    cr_assert_eq(run_app("-t 80"), EX_USAGE, "Only ports");
    cr_assert_eq(run_app("-i IFACE localhost"), EX_USAGE, "Missing port flags (-t/-u)");
    cr_assert_eq(run_app("localhost -t 80"), EX_USAGE, "Missing interface flag");
    cr_assert_eq(run_app("-i IFACE -t 80"), EX_USAGE, "Missing target hostname");
}

Test(cli_logic, port_parsing_success) {
    cr_assert_eq(run_app("-i IFACE -t 20-25 localhost"), EX_OK, "Range");
    cr_assert_eq(run_app("-i IFACE -t 22,80,443 localhost"), EX_OK, "List");
    cr_assert_eq(run_app("-i IFACE -t 1-3,80,443,8080-8081 localhost"), EX_OK, "Complex expression");
    cr_assert_eq(run_app("-i IFACE -t 80 -t 443 localhost"), EX_OK, "Multiple -t flags");
    cr_assert_eq(run_app("-i IFACE -u 53 -u 67 localhost"), EX_OK, "Multiple -u flags");
}

Test(cli_logic, port_parsing_errors) {
    cr_assert_eq(run_app("-i IFACE -t 100-10 localhost"), EX_USAGE, "Reverse range");
    cr_assert_eq(run_app("-i IFACE -t 70000 localhost"), EX_USAGE, "Port too high");
    cr_assert_eq(run_app("-i IFACE -t 0 localhost"), EX_USAGE, "Port zero invalid");
    cr_assert_eq(run_app("-i IFACE -t 22,abc localhost"), EX_USAGE, "String in ports");
    cr_assert_eq(run_app("-i IFACE -t"), EX_USAGE, "Flag with no value");
}

Test(cli_logic, timeout_logic) {
    cr_assert_eq(run_app("-i IFACE -t 80 -w 2000 localhost"), EX_OK, "Valid timeout");
    cr_assert_eq(run_app("-i IFACE -t 80 -w abc localhost"), EX_USAGE, "Invalid string timeout");
    cr_assert_eq(run_app("-i IFACE -t 80 -w 0 localhost"), EX_USAGE, "Zero timeout");
    cr_assert_eq(run_app("-i IFACE -t 80 -w"), EX_USAGE, "Missing timeout value");
}

Test(cli_logic, address_families_and_targets) {
    cr_assert_eq(run_app("-i IFACE -t 22 localhost"), EX_OK, "IPv4 Local");
    cr_assert_eq(run_app("-i IFACE -t 22 127.0.0.1"), EX_OK, "IPv4 Literal");
    cr_assert_eq(run_app("-i IFACE -t 80 2001:67c:1220:809::93e5:917"), EX_OK, "IPv6 Target");
    cr_assert_eq(run_app("-t 80 -i IFACE localhost"), EX_OK, "Random argument order");
    cr_assert_eq(run_app("-i IFACE -t 80 target1 target2"), EX_USAGE, "Multiple targets");
}

Test(cli_logic, interface_validation) {
    cr_assert_eq(run_app("-i non_existent_dev -t 80 localhost"), EX_USAGE);
    cr_assert_eq(run_app("-i IFACE -i IFACE -t 80 localhost"), EX_USAGE, "Duplicate interface flag");
}

Test(cli_logic, full_scan_scenarios) {
    cr_assert_eq(run_app("-i IFACE -t 22,80 -u 53 -w 1500 localhost"), EX_OK, "Standard mixed scan");
    cr_assert_eq(run_app("-i IFACE -t 1-15 -u 50-70 localhost"), EX_OK, "Large range scan");
}