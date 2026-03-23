/**
 * This file is part of the IPK Project 1 - OMEGA: L4 Scanner.
 * // 23.3. 2026 IPK 2026, FIT VUT Brno
 *  Author: Kristian Rucek > xrucekk00
 */

#include <criterion/criterion.h>
#include <string.h>

#include "../src/L4-scan.h"

Test(parse_single_port_suite, valid_values) {
    cr_assert_eq(parse_single_port("1"), 1);
    cr_assert_eq(parse_single_port("22"), 22);
    cr_assert_eq(parse_single_port("65535"), 65535);
}

Test(parse_single_port_suite, invalid_values) {
    cr_assert_eq(parse_single_port("0"), PORT_ERROR);
    cr_assert_eq(parse_single_port("65536"), PORT_ERROR);
    cr_assert_eq(parse_single_port("-10"), PORT_ERROR);
    cr_assert_eq(parse_single_port("abc"), PORT_ERROR);
    cr_assert_eq(parse_single_port("80x"), PORT_ERROR);
}

Test(parse_ports_suite, parses_single_and_list) {
    Config config;
    memset(&config, 0, sizeof(config));

    config.port_string = "22,53,443";

    cr_assert_eq(parse_ports(&config, config.tcp_ports), EX_OK);
    cr_assert(config.tcp_ports[22]);
    cr_assert(config.tcp_ports[53]);
    cr_assert(config.tcp_ports[443]);
    cr_assert(!config.tcp_ports[80]);
}

Test(parse_ports_suite, parses_ranges) {
    Config config;
    memset(&config, 0, sizeof(config));

    config.port_string = "20-25";

    cr_assert_eq(parse_ports(&config, config.tcp_ports), EX_OK);
    for (int p = 20; p <= 25; p++) {
        cr_assert(config.tcp_ports[p]);
    }
    cr_assert(!config.tcp_ports[19]);
    cr_assert(!config.tcp_ports[26]);
}

Test(parse_ports_suite, parses_mixed_expression) {
    Config config;
    memset(&config, 0, sizeof(config));

    config.port_string = "1-3,80,443,8080-8081";

    cr_assert_eq(parse_ports(&config, config.udp_ports), EX_OK);
    cr_assert(config.udp_ports[1]);
    cr_assert(config.udp_ports[2]);
    cr_assert(config.udp_ports[3]);
    cr_assert(config.udp_ports[80]);
    cr_assert(config.udp_ports[443]);
    cr_assert(config.udp_ports[8080]);
    cr_assert(config.udp_ports[8081]);
    cr_assert(!config.udp_ports[8082]);
}

Test(parse_ports_suite, rejects_invalid_expression) {
    Config config;
    memset(&config, 0, sizeof(config));

    config.port_string = "100-10";
    cr_assert_eq(parse_ports(&config, config.tcp_ports), EX_USAGE);

    memset(config.tcp_ports, 0, sizeof(config.tcp_ports));
    config.port_string = "1,abc";
    cr_assert_eq(parse_ports(&config, config.tcp_ports), EX_USAGE);

    memset(config.tcp_ports, 0, sizeof(config.tcp_ports));
    config.port_string = "22,70000";
    cr_assert_eq(parse_ports(&config, config.tcp_ports), EX_USAGE);
}
