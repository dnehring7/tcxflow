// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dirk Nehring <dnehring@gmx.net>
/**
 * @file main.c
 * @brief Command line: run the exporter, or query the running one
 *
 *   tcxflow [OPTIONS]                 run the exporter (default command)
 *   tcxflow [OPTIONS] stats           counters of the running exporter
 *   tcxflow [OPTIONS] interfaces      metered interfaces and their traffic
 *   tcxflow [OPTIONS] check           validate the configuration
 */

#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "collector.h"
#include "config.h"
#include "control.h"
#include "daemon.h"
#include "meter.h"
#include "util.h"

enum { EXIT_OK = 0, EXIT_ERROR = 1, EXIT_USAGE = 2 };

/** A configuration option given on the command line, applied after the configuration file. */
struct cli_option {
    const char *key;   /**< option name without the dashes */
    const char *value; /**< option argument */
};

static void usage(FILE *out) {
    (void)fprintf(out,
                  "tcxflow %s - Lightweight eBPF-based IPFIX flow accounting for Linux\n"
                  "\n"
                  "Usage: tcxflow [OPTIONS] [run|stats|interfaces|check]\n"
                  "\n"
                  "Commands:\n"
                  "  run                   run the exporter in the foreground (default)\n"
                  "  stats                 show the counters of the running exporter\n"
                  "  interfaces            show the metered interfaces and their traffic\n"
                  "  check                 validate the configuration and exit\n"
                  "\n"
                  "Options (also valid as lines \"option value\" in the configuration file):\n"
                  "  -i, --interface IF[:in|:out]  meter interface IF (default: both directions)\n"
                  "      --collector HOST:PORT     send IPFIX to this collector ([ipv6]:port, default port 4739)\n"
                  "      --netns NAME|PATH         the interfaces live in this network namespace\n"
                  "      --inactive-timeout SEC    export a flow after SEC seconds without packets (15)\n"
                  "      --active-timeout SEC      export long flows every SEC seconds (1800)\n"
                  "      --max-flows N             BPF flow table size per second (131072)\n"
                  "      --observation-domain ID   IPFIX observation domain id (1)\n"
                  "  -s, --socket PATH             control socket (%s)\n"
                  "\n"
                  "Other options:\n"
                  "  -c, --config FILE   configuration file (default %s; not read when\n"
                  "                      interfaces or collectors are given on the command line)\n"
                  "  -v, --verbose       show libbpf messages\n"
                  "  -V, --version       print the version and exit\n"
                  "  -h, --help          show this help\n",
                  TCXFLOW_VERSION, CONFIG_DEFAULT_SOCKET, CONFIG_DEFAULT_PATH);
}

/* Validate the configuration and that every collector address resolves. */
static int cmd_check(const struct config *cfg) {
    char err[256];

    for (int i = 0; i < cfg->n_collectors; i++) {
        const int fd = collector_open(cfg->collectors[i], err, sizeof(err));

        if (fd < 0) {
            (void)fprintf(stderr, "tcxflow: %s\n", err);
            return EXIT_ERROR;
        }
        (void)close(fd);
    }
    (void)printf("configuration OK: %d interface(s), %d collector(s)%s%s\n", cfg->n_ifaces, cfg->n_collectors,
                 cfg->netns[0] ? ", netns " : "", cfg->netns);
    return EXIT_OK;
}

/* stats / interfaces: ask the running exporter over the control socket. */
static int cmd_query(const char *socket_path, const char *cmd) {
    if (control_request(socket_path, cmd, stdout)) {
        (void)fprintf(stderr, "tcxflow: cannot reach %s: %s%s\n", socket_path, strerror(errno),
                      errno == ENOENT || errno == ECONNREFUSED ? " (is tcxflow running?)" : "");
        return EXIT_ERROR;
    }
    return EXIT_OK;
}

/**
 * Parse the command line, load the configuration and run the command.
 *
 * @param argc  argument count
 * @param argv  arguments
 * @return 0 on success, 1 on errors, 2 on a usage error
 */
int main(int argc, char **argv) {
    static const struct option options[] = {
        {"interface", required_argument, NULL, 0},
        {"collector", required_argument, NULL, 0},
        {"netns", required_argument, NULL, 0},
        {"inactive-timeout", required_argument, NULL, 0},
        {"active-timeout", required_argument, NULL, 0},
        {"max-flows", required_argument, NULL, 0},
        {"observation-domain", required_argument, NULL, 0},
        {"socket", required_argument, NULL, 0},
        {"config", required_argument, NULL, 'c'},
        {"verbose", no_argument, NULL, 'v'},
        {"version", no_argument, NULL, 'V'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0},
    };
    static struct config cfg;
    static struct cli_option cli[256];
    const char *config_path = NULL;
    const char *cmd = "run";
    bool cli_targets = false; // interfaces or collectors on the command line
    bool verbose = false;
    char err[512];
    int n_cli = 0;
    int opt = 0;
    int idx = 0;

    while ((opt = getopt_long(argc, argv, "i:s:c:vVh", options, &idx)) != -1) {
        const char *key = NULL;

        switch (opt) {
            case 0:
                key = options[idx].name;
                break;
            case 'i':
                key = "interface";
                break;
            case 's':
                key = "socket";
                break;
            case 'c':
                config_path = optarg;
                continue;
            case 'v':
                verbose = true;
                continue;
            case 'V':
                (void)printf("tcxflow %s\n", TCXFLOW_VERSION);
                return EXIT_OK;
            case 'h':
                usage(stdout);
                return EXIT_OK;
            default:
                usage(stderr);
                return EXIT_USAGE;
        }
        if (n_cli == (int)(sizeof(cli) / sizeof(cli[0]))) {
            (void)fprintf(stderr, "tcxflow: too many options\n");
            return EXIT_USAGE;
        }
        cli[n_cli++] = (struct cli_option){.key = key, .value = optarg};
        cli_targets |= !strcmp(key, "interface") || !strcmp(key, "collector");
    }
    if (optind < argc)
        cmd = argv[optind++];
    if (optind < argc || (strcmp(cmd, "run") != 0 && strcmp(cmd, "stats") != 0 && strcmp(cmd, "interfaces") != 0 &&
                          strcmp(cmd, "check") != 0)) {
        usage(stderr);
        return EXIT_USAGE;
    }

    // Configuration file first, command line options on top. Interfaces or collectors on the
    // command line skip the default file: a quick manual test must not add to the interfaces
    // and collectors of the installed service.
    config_init(&cfg);
    if (!config_path && !cli_targets && !access(CONFIG_DEFAULT_PATH, F_OK))
        config_path = CONFIG_DEFAULT_PATH;
    if (config_path && config_load(&cfg, config_path, err, sizeof(err))) {
        (void)fprintf(stderr, "tcxflow: %s\n", err);
        return EXIT_ERROR;
    }
    for (int i = 0; i < n_cli; i++) {
        if (config_set(&cfg, cli[i].key, cli[i].value, err, sizeof(err))) {
            (void)fprintf(stderr, "tcxflow: --%s: %s\n", cli[i].key, err);
            return EXIT_USAGE;
        }
    }

    if (!strcmp(cmd, "stats") || !strcmp(cmd, "interfaces"))
        return cmd_query(cfg.socket, cmd);
    if (config_validate(&cfg, err, sizeof(err))) {
        (void)fprintf(stderr, "tcxflow: %s (see tcxflow --help)\n", err);
        return EXIT_ERROR;
    }
    if (!strcmp(cmd, "check"))
        return cmd_check(&cfg);

    (void)setvbuf(stderr, NULL, _IOLBF, 0);
    meter_set_verbose(verbose);
    return daemon_run(&cfg);
}
