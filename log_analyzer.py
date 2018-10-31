#!/usr/bin/env python
# -*- coding: utf-8 -*-


# log_format ui_short '$remote_addr  $remote_user $http_x_real_ip [$time_local] "$request" '
#                     '$status $body_bytes_sent "$http_referer" '
#                     '"$http_user_agent" "$http_x_forwarded_for" "$http_X_REQUEST_ID" "$http_X_RB_USER" '
#                     '$request_time';

import argparse
import gzip
import json
import logging
import os
import re
import statistics
import sys
from bisect import insort_right
from datetime import datetime
from typing import NamedTuple, Optional, Dict, Tuple, Iterable, List, Union
from string import Template


APP_LOG_PATH = "./app_logs/log_analyzer_log"
logging.basicConfig(filename=APP_LOG_PATH if os.path.isfile(APP_LOG_PATH) else None,
                    format="[%(asctime)s] %(levelname).1s %(message)s",
                    datefmt="%Y.%m.%d %H:%M:%S",
                    level=logging.INFO)
logger = logging.getLogger(".config.cfg")


config = {
    "REPORT_SIZE": 100,
    "REPORT_DIR": "./reports",
    "LOG_DIR": "./log"
}

REPORT_NAME_PATTERN = "report-{}.html"
LOG_NAME_PATTERN = r"nginx-access-ui.log-(\d{8}|\d{8}\.gz)$"
LOG_EXTENSION = ".gz"
DEFAULT_CONFIG_PATH = "config.cfg"


class LogFile(NamedTuple):
    path_to_file: str
    file_name: str
    date_in_file_name: str
    extension: Optional[str]


def find_newest_log_file(log_dir: str) -> Optional[LogFile]:

    compiled_pattern = re.compile(LOG_NAME_PATTERN)
    log_files = []

    for file in os.listdir(log_dir):
        if not compiled_pattern.match(file):
            continue
        insort_right(log_files, file)
    if not log_files:
        logger.info("No files in log directory {}".format(log_dir))
        return None

    newest_log = log_files[-1]
    newest_log_date = _get_date_in_the_name(newest_log)

    return LogFile(path_to_file=log_dir,
                   file_name=newest_log,
                   date_in_file_name=newest_log_date,
                   extension=LOG_EXTENSION if newest_log.endswith(LOG_EXTENSION) else None)


def _get_date_in_the_name(log_file_name: str):
    stripped_date = log_file_name.split("-")[3].split(".")[0]
    return datetime.strptime(stripped_date, "%Y%m%d").strftime("%Y.%m.%d")


def build_report_path(report_dir: str, report_date: str) -> str:
    return os.path.join(report_dir, REPORT_NAME_PATTERN.format(report_date))


def report_exists(report_path: str) -> bool:
    return os.path.isfile(report_path)


def log_parser(log_file: LogFile) -> Iterable[Tuple[str, str]]:

    log_path = os.path.join(log_file.path_to_file, log_file.file_name)
    file_opener = open if not log_file.extension else gzip.open

    with file_opener(log_path, mode="rt", encoding="utf-8") as file:

        while True:
            log_row = next(file).split(" ")
            request_url = log_row[7]
            request_time = float(log_row[-1])

            yield request_url, request_time


def analyze_log(parser: Iterable[Tuple[str, str]]) -> Dict[str, Dict[str, Union[int, List[float]]]]:

    snippets = {
        "totals": {"total_requests": 0,
                   "total_time": 0},
        "urls": {}
        }
    for url_and_time in parser:
        request_url, request_time = url_and_time
        snippets["totals"]["total_requests"] += 1
        snippets["totals"]["total_time"] += request_time

        if request_url not in snippets:
            snippets["urls"].update({request_url: {"count": 1,
                                                   "request_times": [request_time]}})
            continue
        snippets[request_url]["count"] += 1
        snippets[request_url]["request_times"].append(request_time)

    return snippets


def count_stats(parsed_log: dict, report_size: int) ->List[dict]:

    _report = []

    for key, value in parsed_log.items():
        if key == "totals":
            total_requests = value["total_requests"]
            total_time = value["total_time"]
        if key == "urls":
            for url, counts in value.items():
                time_sum = sum(counts["request_times"])
                time_avg = time_sum/len(counts["request_times"])
                time_max = max(counts["request_times"])
                time_med = statistics.median(counts["request_times"])
                count_perc = counts["count"] * total_requests / 100
                time_perc = time_sum * total_time / 100

                _report.append({
                    "url": url,
                    "count": counts["count"],
                    "count_perc": count_perc,
                    "time_sum": time_sum,
                    "time_perc": time_perc,
                    "time_avg": time_avg,
                    "time_max": time_max,
                    "time_med": time_med
                })
    _sorted_report = sorted(_report, key=lambda item: item["count"])
    final_report = _sorted_report[0:report_size]

    return final_report


def create_report(report_dir: str, final_report: List[dict], report_date: str):
    with open(os.path.join(report_dir, "report.html"), encoding="utf-8") as file:
        html_template = Template(file.read())
    final_template = html_template.safe_substitute(table_json=json.dumps(final_report))

    with open(os.path.join(report_dir, REPORT_NAME_PATTERN.format(report_date)), mode="w") as file:
        file.write(final_template)


def parse_args(app_name) -> argparse.Namespace:
    parser = argparse.ArgumentParser(app_name)
    parser.add_argument("--config", help="path to config file", default=DEFAULT_CONFIG_PATH)
    return parser.parse_args()


def load_config_file(external_config_path: str) -> Optional[Dict[str, str]]:
    try:
        loaded_config = json.load(open(external_config_path, "r"))
        return loaded_config
    except FileNotFoundError as e:
        logger.error("Passed config not found. {}".format(e))
        return
    except ValueError as e:
        logger.error("Passed config is not valid. {}".format(e))
        return


def get_config_params(loaded_config: Dict[str, str]) -> Optional[Tuple[str, str, str]]:
    report_size = loaded_config.get("REPORT_SIZE", config["REPORT_SIZE"])
    report_dir = loaded_config.get("REPORT_DIR", config["REPORT_DIR"])
    log_dir = loaded_config.get("LOG_DIR", config["LOG_DIR"])

    return report_size, report_dir, log_dir


def main():
    args = parse_args(__file__)

    loaded_config = load_config_file(args.config)
    if not loaded_config and not isinstance(loaded_config, dict):
        sys.exit(1)

    report_size, report_dir, log_dir = get_config_params(loaded_config)
    if not os.path.isdir(log_dir):
        logger.error("Log directory doesn't exist.")
        sys.exit(1)
    newest_log = find_newest_log_file(log_dir)
    if not newest_log:
        sys.exit(0)
    report_path = build_report_path(report_dir, newest_log.date_in_file_name)
    if report_exists(report_path):
        logger.info("Report is already exist {}".format(report_path))
        sys.exit()

    parser = log_parser(newest_log)

    snippets = analyze_log(parser)

    final_report = count_stats(snippets, report_size)
    create_report(report_dir, final_report, newest_log.date_in_file_name)


if __name__ == "__main__":
    main()