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
from copy import deepcopy
import dateparser
import logging
import math
import multiprocessing
from pprint import pformat
import re
import requests
import time
import yaml

log = logging.getLogger("zabbix-report.zabbix")


class ZabbixQuery(object):
    def __init__(self, config_file, reports_file, debug=False):
        try:
            config = yaml.safe_load(open(config_file, 'r').read())
        except Exception as e:
            log.fatal("Couldn't load config file {}: {}".format(config_file, e))
            exit(1)
        self.debug = debug
        self.session = requests.Session()
        self.zabbix_url = config["zabbix"]["url"]
        self.session.headers.update({"Content-Type": "application/json-rpc"})
        self.authtoken = self._get_auth(config["zabbix"]["user"], config["zabbix"]["password"])
        try:
            reports = yaml.safe_load(open(reports_file, 'r').read())
        except Exception as e:
            log.fatal("Couldn't load config file {}: {}".format(config_file, e))
            exit(1)
        self.reports = reports["reports"]
        self.history_chunk_size = reports.get("history_chunk_size", 5)
        self.item_chunk_size = reports.get("item_chunk_size", 150)
        self.item_processors = reports.get("host_query_threads", 3)
        self.history_processors = reports.get("history_query_threads", 6)

    def _get_auth(self, user, password):
        authdata = {"jsonrpc": "2.0",
                    "method": "user.login",
                    "id": 1,
                    "auth": None}
        authdata["params"] = {"user": user, "password": password}
        try:
            res = self.session.post(self.zabbix_url, json=authdata)
        except Exception as e:
            log.fatal("Could not retrieve auth token from {}: {}".format(self.zabbix_url, e))
            exit(2)
        if res.status_code != 200:
            log.fatal("Bad return from {}: {}".format(self.zabbix_url, res.text))
            exit(2)
        try:
            authtoken = res.json()["result"]
        except Exception as e:
            log.fatal("Couldn't de-serialize return ({}) from {}: {}".format(res.text, self.zabbix_url, e))
            exit(1)
        return authtoken

    def _zabbix_cmd(self, method, params={}):
        data = {"jsonrpc": "2.0",
                "method": method,
                "id": 1,
                "auth": self.authtoken,
                "params": params}
        log.debug("Running {} with {}".format(method, pformat(data)))
        res = ""
        count = 0
        while not res and count < 10:
            try:
                res = self.session.post(self.zabbix_url, json=data)
            except Exception as e:
                log.fatal("Failed to execute {}: {}".format(method, e))
                res = {}
            else:
                if res.status_code >= 400 or res.status_code < 200:
                    log.fatal("Bad results from Zabbix for {}: {}".format(method, res.text))
                    res = {}
            if not res:
                log.debug("Giving Zabbix a quick break...")
                time.sleep(3)
        if count >= 10 or not res:
            log.fatal("Tried to collect {} from Zabbix {} times without success".format(data, count))
            exit(2)
        try:
            res = res.json()["result"]
        except Exception as e:
            log.error("Bad data returned from Zabbix for {}: {} (data: {})".format(method, e, res.text))
            log.info("Initial POST: {}".format(data))
            if self.debug:
                exit(1)
            return {}
        return res

    def _get_item_chunk(self, params):
        """
        Actually retrieve one chunk of data from Zabbix about items
        We return this regularly so the multiprocessing map works correctly
        """
        chunk = params.pop("chunk", None)
        if chunk > 0 and chunk % 100 == 0:
            log.info("Processing host chunk {}".format(chunk))
        log.debug("item params: {}".format(params))
        return self._zabbix_cmd("item.get", params)

    def _item_chunk(self, hosts, groups, app):
        """
        Get data about items associated to specified host/group/app
        Return as a generator so we can process efficiently
        """
        params = {}
        if app:
            params["application"] = app
        if groups:
            params["groupids"] = groups
        if hosts:
            hostids = [k for k in hosts.keys()]
            param_chunks = []
            for i in range(0, len(hostids), self.item_chunk_size):
                params["chunk"] = i
                params["hostids"] = hostids[i:i + self.item_chunk_size]
                param_chunks.append(deepcopy(params))
            pool = multiprocessing.Pool(processes=self.item_processors)
            for results in pool.imap_unordered(self._get_item_chunk, param_chunks, chunksize=100):
                for item in results:
                    yield item
        else:
            for item in self._zabbix_cmd("item.get", params):
                yield item

    def prep_report(self, report_name, report):
        """
        Here we actually query Zabbix for the items we actually need to generate our reports
        """
        full_report = deepcopy(report)
        if "item" not in report or not report["item"]:
            log.warning("Reports must have items! {}".format(report))
            return {}

        """
        Configure aggregation for the report (if any)
        """
        thisagg = report.get("aggregation", {"type": "item"})
        report["aggregation"] = dict(thisagg)
        if thisagg["type"] == "item_regex":
            report["aggregation"]["match"] = re.compile(thisagg["pattern"])
        elif thisagg["type"] == "hostgroup":
            report["aggregation"]["match"] = thisagg["group"]
        elif thisagg["type"] == "item":
            report["aggregation"]["match"] = None

        # ensure trends key exists
        full_report["trends"] = report.get("trends", {"use_trends": False})

        """
        hostgroup discovery and filtering
        """
        hostgroup = report.get("hostgroup", None)
        if hostgroup:
            hgs = self._zabbix_cmd("hostgroup.get", {"monitored_hosts": True, "selectHosts": "extend",
                                                     "filter": {"name": [hostgroup]}})
            log.debug("Hostgroups: {}".format(pformat(hgs)))
            hg_ids = [h["groupid"] for h in hgs]
        else:
            hgs = None
            hg_ids = []
        """
        host discovery and filtering
        """
        if report.get("hosts", None):
            """
            `hosts` should always be a regex pattern
            """
            host_re = re.compile(report["hosts"])
            found_hosts = {}
            if hostgroup:
                found_hosts = {h["hostid"]: h for hg in hgs for h in hg["hosts"]}
            else:
                found_hosts = self._zabbix_cmd("host.get", {"monitored_hosts": True})
                found_hosts = {h["hostid"]: h for h in found_hosts}
            hosts = {k: v for k, v in found_hosts.items() if host_re.fullmatch(v["host"])}
            log.debug("Matched {} hosts".format(len(hosts.keys())))
        else:
            found_hosts = self._zabbix_cmd("host.get", {"monitored_hosts": True})
            hosts = {h["hostid"]: h for h in found_hosts}
        """
        Actual item discovery and filtering
        """
        item_re = re.compile(report["item"])
        full_report["items"] = {}
        for i in self._item_chunk(hosts, hg_ids, report.get("application", None)):
            itemid = i["itemid"]
            if not item_re.fullmatch(i["name"]):
                continue
            full_report["items"][itemid] = i
            full_report["items"][itemid]["grouping"] = self._get_grouping(report["aggregation"], i["name"],
                                                                          hosts[i["hostid"]]["host"], hostgroup)
        log.debug("Items: {}".format(pformat(full_report["items"])))
        return full_report

    def _get_grouping(self, agg, itemname, hostname, hostgroup):
        if agg["type"] == "item":
            return hostname
        elif agg["type"] == "hostgroup":
            return hostgroup
        elif agg["type"] == "item_regex":
            res = agg["match"].match(itemname)
            match = res.group(1)
            if agg.get("ignore_case", False):
                res = match.lower()
            return res

    def _convert_value(self, value):
        """
        We'll handle converting from a string to a number here ('cause Zabbix's API only returns strings)
        """
        if "." in value:
            value = float(value)
        else:
            value = int(value)
        return value

    def _get_history_chunk(self, params):
        """
        Actually retrieve one chunk of history data from Zabbix
        We return this regularly so the multiprocessing map works correctly
        """
        chunk = params.pop("chunk")
        trends = params.pop("trends")
        if chunk > 0 and chunk % 100 == 0:
            log.info("Procesing item chunk {}...".format(chunk))
        log.debug("History params: {}".format(pformat(params)))
        if trends["use_trends"]:
            params["output"] = ["itemid", "clock", trends["value"]]
            res = self._zabbix_cmd("trend.get", params)
            output = []
            # Not a list comprehension 'cause we're replacing values, not simply appending
            for v in res:
                v["value"] = v.pop(trends["value"])
                output.append(v)
            return output
        else:
            return self._zabbix_cmd("history.get", params)

    def _history_chunk(self, report):
        """
        Returns chunks of history data as they are retrieved.
        """
        params = {}
        if report.get("time_range", None):
            """
            dateparser handles turning something like `30d` into an actual datetime object
            which we can then turn into the timestamp Zabbix requires
            """
            parsed_date = dateparser.parse(report["time_range"],
                                           settings={"TO_TIMEZONE": "UTC"})
            params["time_from"] = int(parsed_date.timestamp())
        elif report.get("time_from", None):
            """
            dateparser handles turning something like `30d` into an actual datetime object
            which we can then turn into the timestamp Zabbix requires
            """
            parsed_date = dateparser.parse(report["time_from"],
                                           settings={"TO_TIMEZONE": "UTC"})
            params["time_from"] = int(parsed_date.timestamp())
            if report.get("time_till", None):
                parsed_date = dateparser.parse(report["time_till"],
                                               settings={"TO_TIMEZONE": "UTC"})
                params["time_till"] = int(parsed_date.timestamp())

        params["trends"] = dict(report["trends"])
        itemids = list(report["items"].keys())
        param_chunks = []
        for i in range(0, len(itemids), self.history_chunk_size):
            params["itemids"] = itemids[i:i + self.history_chunk_size]
            params["chunk"] = i
            param_chunks.append(deepcopy(params))
        pool = multiprocessing.Pool(processes=self.history_processors)
        for results in pool.imap_unordered(self._get_history_chunk, param_chunks, chunksize=100):
            for item in results:
                yield item

    def get_history(self, report):
        """
        Actually get history data about items selected

        Zabbix results really aren't designed for easy modification:
        [
            {
                "itemid": "23296",
                "clock": "1351090996",
                "value": "0.0850",
                "ns": "563157632"
            },
            {
                "itemid": "23296",
                "clock": "1351090936",
                "value": "0.1600",
                "ns": "549216402"
            },
        ]
        Consequently, we have to loop through each data point and sort it into
        objects where we can actually do math

        Generator to help speed up processing...hopefully
        """
        history_output = {}
        for point in self._history_chunk(report):
            itemid = point["itemid"]
            # For better discovery afterwards, we'll sort by grouping *and* item name
            grouping = report["items"][itemid]["grouping"]
            itemname = report["items"][point["itemid"]]["name"]
            value = self._convert_value(point["value"])
            if grouping in history_output:
                if itemname in history_output[grouping]:
                    history_output[grouping][itemname]["data"].append(value)
                else:
                    history_output[grouping][itemname] = {"data": [value]}
            else:
                history_output[grouping] = {}
                history_output[grouping][itemname] = {"data": [value]}

        return history_output

    def _percent_calc(self, data, percentage):
        """
        based on https://code.activestate.com/recipes/511478-finding-the-percentile-of-the-values/
        """
        if percentage < 0 or percentage > 1:
            raise RuntimeError("Bad percentage for calc!")
        k = (len(data) - 1) * percentage
        data.sort()
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return data[int(k)]
        d0 = data[int(f)] * (c - k)
        d1 = data[int(c)] * (k - f)
        return d0 + d1

    def _do_calc(self, data, func):
        if func == "sum":
            return sum(data)
        elif func == "avg":
            return sum(data) / len(data)
        elif func == "count":
            return len(data)
        elif func == "max":
            return max(data)
        elif func == "min":
            return min(data)
        elif func == "99th_percent":
            return self._percent_calc(data, 0.99)
        elif func == "95th_percent":
            return self._percent_calc(data, 0.95)
        elif func == "90th_percent":
            return self._percent_calc(data, 0.90)
        elif func == "75th_percent":
            return self._percent_calc(data, 0.75)
        elif func == "50th_percent":
            return self._percent_calc(data, 0.5)

    def calculation(self, report, history_output):
        """
        Calcuation time!
        """
        results = {}
        for grouping, items in history_output.items():
            for itemname, item in items.items():
                if grouping in results:
                    results[grouping][itemname] = {"result": self._do_calc(item["data"], report["calculation"])}
                else:
                    results[grouping] = {itemname: {"result": self._do_calc(item["data"], report["calculation"])}}
        log.debug("Basic math...{}".format(pformat(results)))
        output = {}
        if report.get("aggregation", {}).get("sum_items", False):
            for grouping in results.keys():
                value = sum(item["result"] for item in results[grouping].values())
                output[grouping] = value
        else:
            output = deepcopy(results)

        data = {"data": output}
        if "time_range" in report:
            data["time_range"] = report["time_range"]
        elif "time_from" in report:
            data["time_from"] = report["time_from"]
            if "time_till" in report:
                data["time_till"] = report["time_till"]
        return data
