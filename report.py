#!/usr/bin/env python3
"""
 * This file is part of zabbix-aggregate-reports.
 *
 * Copyright Datto, Inc.
 * Author: John Seekins <jseekins@datto.com>
 *
 * Licensed under the GNU General Public License Version 3
 * Fedora-License-Identifier: GPLv3+
 * SPDX-2.0-License-Identifier: GPL-3.0+
 * SPDX-3.0-License-Identifier: GPL-3.0-or-later
 *
 * zabbix-aggregate-reports is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * zabbix-aggregate-reports is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with zabbix-aggregate-reports.  If not, see <https://www.gnu.org/licenses/>.
 *
"""
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
import json
import logging
import os
from pprint import pformat
import sys
SCRIPTDIR = os.path.dirname(os.path.realpath(__file__))
sys.path.append(SCRIPTDIR)
from lib.zabbix_reporting import ZabbixQuery


def cli_opts():
    parser = ArgumentParser(description="Load/create aggregate reporting data from Zabbix",
                            formatter_class=ArgumentDefaultsHelpFormatter)
    parser.add_argument("-c", "--config-file", default="{}/config.yml".format(SCRIPTDIR),
                        help="config file path to load")
    parser.add_argument("-r", "--reports-file", default="{}/reports.yml".format(SCRIPTDIR),
                        help="reports file path to load")
    parser.add_argument("--output-path", default="{}/report_output/".format(SCRIPTDIR), help="path to write results files to")
    parser.add_argument("--output-raw", action="store_true", default=False, help="Save the raw data used in the calculations")
    parser.add_argument("--debug", action="store_true", default=False,
                        help="Show debug information")
    return parser.parse_args()


def main():
    args = cli_opts()
    log = logging.getLogger("zabbix-report")
    log.setLevel(logging.INFO)
    ch = logging.StreamHandler()
    logformat = "%(asctime)s %(levelname)s %(message)s"
    formatter = logging.Formatter(logformat)
    ch.setFormatter(formatter)
    log.addHandler(ch)
    if args.debug:
        log.setLevel(logging.DEBUG)
    if not os.path.exists(args.output_path):
        os.makedirs(args.output_path)
    zbx = ZabbixQuery(args.config_file, args.reports_file, args.debug)
    for report_name, report in zbx.reports.items():
        log.info("Collecting host/item information for {}...".format(report_name))
        full_report = zbx.prep_report(report_name, report)
        if not full_report:
            continue
        log.info("Collecting data for reports...")
        historydata = zbx.get_history(full_report)
        results = zbx.calculation(full_report, historydata)
        results[report_name] = results.pop("data")
        log.info(pformat(results))
        if args.output_path:
            with open("{}/{}.json".format(args.output_path, report_name), "w") as f_out:
                json.dump(results, f_out)
            if args.output_raw:
                with open("{}/{}-raw.json".format(args.output_path, report_name), "w") as f_out:
                    json.dump(historydata, f_out)


if __name__ == '__main__':
    main()
