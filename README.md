# Zabbix Reporting

This is a relatively simple tool that will aggregate data returned from Zabbix (based on hostgroup/application/item/host).

Developed for python3. Requirements listed in `requirements.txt`.

# Important Note
Zabbix's API does not allow for results pagination. Consequently, much larger queries may simply time out instead of returning properly. While this tool attempts to mitigate that by "chunking" queries into small amounts, there may still be query failures because of this limitation.

# Grouping results
Results can be grouped in many ways using the `aggregation` setting in a report.

Currently available aggregation/grouping choices:

* `item_regex`
  * Use a regex to match items into groups for aggregation (particularly helpful if a number of items have a logical group that can't be represented by a hostgroup).
* `hostgroup`
  * Group items by a Zabbix hostgroup.
* `item`
  * The default. Group items at a host object level.

This step can also define whether we want individual items per group, or a single value per group using the `sum_items` switch.

# Using the `trends` table

Zabbix has two tables that store data about items: `history` and `trends`. The `history` table is the initial "raw" table that data is stored in. The `trends` table stores data at a one (1) hour interval using the following aggregations:

* min (`value_min`)
* max (`value_max`)
* avg (`value_avg`)

These values can be used in place of the `history` table to produce our aggregates. Using `trends` will be _significantly_ faster than `history` for larger groups (e.g. 1000+ hosts) but does potentially lose accuracy.

By default, reports will use the `history` table, but reports can be configured to use the trends table.

# Outputing results
Results will output to files using the `--output-path` CLI switch. Each report will be written to a file with the report name.

## Reports Options

* `reports`
  * object containing all reports to be run
* `history_chunk_size`
  * number of items to include in individual history queries to Zabbix
  * default: `5`
* `item_chunk_size`
  * number of host objects to include in individual item queries to Zabbix
  * default: `150`
* `host_query_threads`
  * number of parallel query threads to perform for items
  * default: `3`
* `history_query_threads`
  * number of parallel threads to use for history data queries
  * default: `6`

### `reports` object details

Each report object should start with a unique name.

* `hostgroup`
  * a single hostgroup we'll be aggregating on
  * not required
* `trends`
  * Configure this report to use the trends table instead of the history table -> this will be faster, but potentially lose some accuracy
  * `use_trends`
    * to ensure the query hits the right table (true/false)
    * default: false
  * `value`
    * the trends key to collect (`value_min`, `value_max`, `value_avg`)
* `aggregation`
  * should we reduce the returned values? The default is to return numbers per host object.
  * `type`
    * what type/level of aggregation we should perform (`item_regex`, `hostgroup`, `item` <default>)
  * `group`
    * when using `hostgroup` aggregation, what hostgroup we should aggregate to
  * `pattern`
    * when using `item_regex` aggregation, this is our regex. This value should be enclosed in single quotes `'` (instead of `"`) to avoid interpolation problems.
  * `ignore_case`
    * when using `item_regex` aggregation, whether we should consider `item` and `ITEM` to be the same aggregation group. (true/false)
    * default: false
  * `sum_items`
    * whether to make one value per aggregation group, or display each discovered item individually (true/false)
    * math performed is a sum to avoid reducing accuracy
* `application`
  * what application items are associated with
  * not required
* `hosts`
  * regex matching hosts associated
  * not required (blank implies _all_ hosts)
* `item`
  * regex matching item names
  * required field
* `calculation`
  * aggregation calculation to perform
  * required field
* `time_range`
  * Fuzzy time range (e.g. 1w, 30d, etc.)
  * overrides `time_from`/`time_till`
* `time_from`
  * explicit time range (e.g. Saturday, September 26th, 2020)
* `time_till`
  * requires `time_from`
  * explicit time range (e.g. Thursday, October 1st, 2020)

# Example Report
```
reports:
  provider_traffic:
    hostgroup: networks
    aggregation:
      sum_items: true
      type: item_regex
      pattern: '.*PROVIDER:(\w+).*'
      ignore_case: true
    application: Provider Interface Traffic
    hosts: ".*"
    item: "Ethernet.*PROVIDER:(provider1|provider2).*Inbound 5m Traffic"
    calculation: sum
    time_range: 30d
```

This report filters down to:

1. host in the `NETENG` hostgroup
2. with items in the application `Provider Interface Traffic`
3. and items matching the naming pattern `Ethernet.*PROVIDER:(provider1|provider2).*Inbound 5m Traffic`
4. And aggregate those results into a single item per the item pattern.

We then request the last 30 days of data and sum that

## Example results
```
INFO Collecting host/item information for reports...
INFO Collecting data for reports...
INFO {'provider_traffic': {'provider1': 343947171874894.4,
                      'provider2': 28713215181790.797},
 'time_range': '30d'}
```

# Available calculation functions
* `avg`
	* sum all values for an item and divide by the number of values found
* `count`
	* count of values found for an item
* `max`
	* max value found for an item
* `min`
	* max value found for an item
* `sum`
	* sum all values found for an item
* `99th_percent`
    * return the 99th percentile value of the item
* `95th_percent`
    * return the 95th percentile value of the item
* `90th_percent`
    * return the 90th percentile value of the item
* `75th_percent`
    * return the 75th percentile value of the item
* `50th_percent`
    * return the 50th percentile value of the item

# Auth

The configuration file needs a section describing the Zabbix endpoint to hit and the user credentials to use:
```
zabbix:
  url: https://zabbix.example.com/api_jsonrpc.php
  user:
  password:
```

# CLI Options

```
python3 report.py -h
usage: report.py [-h] [-c CONFIG_FILE] [-r REPORTS_FILE] [--output-path OUTPUT_PATH] [--debug]

Get duplicate hosts

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG_FILE, --config-file CONFIG_FILE
                        config file path to load (default: config.yml)
  -r REPORTS_FILE, --reports-file REPORTS_FILE
                        reports file path to load (default: reports.yml)
  --output-path OUTPUT_PATH
                        path to write results files to (default: None)
  --output-raw          Save the raw data used in the calculations (default: False)
  --debug               Show debug information (default: False)
```

# Licensing

zabbix-aggregate-reports is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, under version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

