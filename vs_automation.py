#!/usr/bin/python3

import argparse
import sys
import os
import requests
import json
from requests.exceptions import HTTPError
from datetime import datetime

from config.config import auth, urls
from utils.utils import hash_file


def file_url_report(endpoint, api_key, url=None, hash_type=None, scan_id=None):
    """
    Retrieves the most recent antivirus report from /file/report or /url/report.
    :param scan_id: Retrieve report by scan id of file scanned.
    :param endpoint: URL for type of report to grab.
    :param api_key: API key for virus total.
    :param url: If running url report, set url = url, else leave None.
    :param hash_type: Hash algorithm of file.
    :return: Returns the report of the scan.
    """

    # Check to see if md5 hash or url provided in params
    if hash_type:
        resource_type = hash_type
    elif url:
        resource_type = url
    else:
        resource_type = scan_id
    params = {
        "apikey": api_key,
        "resource": resource_type,
    }
    report = ""
    response = ""
    try:
        # Get response from server
        response = requests.get(endpoint, params)
        # None if response code <200>, HTTPError if otherwise
        response.raise_for_status()
        report = response.json()
    # Print the response code and Exception
    except HTTPError as e:
        print("Exception: {}, {}".format(response.raise_for_status(), str(e)))
    # Check results of scan returned from API
    if not report["response_code"] == 1:
        print(report["verbose_msg"])
        sys.exit(0)
    else:
        # Prints some results and returns the dictionary of PSPs.  Can Do whatever here.
        scans_dict = report["scans"]
        print(
            "Scan ID: {}\n"
            "Resource {}\n"
            "Scan Date: {}\n"
            "Link to Scan: {}\n"
            "Total Scans: {} \n"
            "Positive Hits: {}".format(
                report["scan_id"],
                report["resource"],
                report["scan_date"],
                report["permalink"],
                report["total"],
                report["positives"],
            )
        )
        return report


def file_scan(endpoint, api_key, file):
    """
    :param endpoint: URL for Virus Total API Endpoint.
    :param api_key: API Key for Virus Total.
    :param file: File to be scanned.
    :return: Scan results to lookup report.
    """
    params = {
        "apikey": api_key,
        "file": (file, open(file, 'rb'))
    }
    scan = ""
    response = ""
    try:
        # Get response from server
        response = requests.post(endpoint, params)
        # None if response code <200>, HTTPError if otherwise
        response.raise_for_status()
        scan = response.json()
    # Print the response code and Exception
    except HTTPError as e:
        print("Exception: {}, {}".format(response.raise_for_status(), str(e)))
    # Check results of scan returned from API
    if not scan["response_code"] == 1:
        print(scan["verbose_msg"])
        sys.exit(0)
    else:
        # Print response from the scan
        print(
            "Scan ID: {}\n"
            "Resource {}\n"
            "Link to Scan: {}\n"
            "Verbose Message: {}".format(
                scan["scan_id"],
                scan["resource"],
                scan["permalink"],
                scan["verbose_msg"],
            )
        )
        return scan


def get_file_upload_url(endpoint, api_key, file):
    """
    This does not work with the public API.  This API requires additional privileges. Please contact us if you
    need to upload files bigger than 32MB in size.
    :param endpoint: url for the /file/scan/upload_url endpoint.
    :param apikey: API key for Virus Total
    :param file: File to be scanned
    :return: Returns the scan response for the server.
    """
    params = {
        "apikey": api_key,
    }
    upload_url = ''
    response = ''
    try:
        # Fetches a special url to submit file to server
        response = requests.post(endpoint, params)
        # None if response code <200>, HTTPError if otherwise
        response.raise_for_status()
        upload_url = response.json()
        # Print the response code and Exception
    except HTTPError as e:
        print("Exception: {}, {}".format(response.raise_for_status(), str(e)))

    files = {
        "file": (file, open(file, 'rb'))
    }
    # Scan using the upload url
    scan_response = ''
    try:
        scan_response = requests.post(upload_url, files)
        scan_response.raise_for_status()
    except HTTPError as e:
        print("Status Code: {}, Exception: {}".format(response.status_code, str(e)))

    return scan_response.text


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="This program interacts with the Virus Total public API, and is "
        "intended to work with Linux. \nTo use, you first need to store your "
        "API key in your systems environment variables which as so:"
        "export VT_API_KEY = 'your-api-key'."
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 1.0",
    )
    parser.add_argument(
        "-f",
        "--file",
        metavar="File",
        type=str,
        required=False,
        help="File to be hashed and submitted to /file/report endpoint.",
    )
    parser.add_argument(
        "-u",
        "--url",
        metavar="URL_Report",
        type=str,
        required=False,
        help="Retrieves the most recent antivirus report of the URL from /url/report endpoint.",
    )
    # parser.add_argument(
    # 'F',
    # '--file_list',
    # metavar='File_List',
    # FileType=str,
    # required=False,
    # help='Parses a file of hashes to be submitted to /file/report endpoint.'
    # )
    parser.add_argument(
        "-S",
        "--file_scan",
        metavar="File_Scan",
        required=False,
        help="Submit a file to be scanned to the /file/scan endpoint. Will return a scan id. Max file size is 32MB."
        "If file is larger than 32MB, use /file/scan/upload.",
    )
    parser.add_argument(
        "-si",
        "--scan_id",
        metavar="Scan_ID",
        type=str,
        required=False,
        help="Retrieves the most recent antivirus report from /file/report using the scan_id returned "
        "from /file/scan endpoint.",
    )
    parser.add_argument(
        "-H",
        "--hash",
        metavar="Hash",
        type=str,
        required=False,
        choices=["md5", "sha1", "sha256"],
        help="Set the hash algorithm (md5, sha1, sha256) to submit to /file/report. Used in conjunction"
        "with --file.",
    )
    parser.add_argument(
        "-U",
        "--upload_large_file",
        metavar="Upload_Large_File",
        type=str,
        required=False,
        help="For files 32MB-200MB in size. Generates a special upload url from /file/scan/upload_url endpoint, and "
             "submits the file to be scanned. Does not work with the public API. This API requires additional "
             "privileges. Please contact us if you need to upload files bigger than 32MB in size."
    )
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()
    filename = str(datetime.now().strftime("%m%d%Y_%H-%M-%S"))

    # Grab the api key from environment variables
    api_key = ""
    try:
        api_key = auth["api_key"]
    except KeyError:
        print("Environment variable does not exist, or can not be accessed.")

    if args.file and args.hash:
        if not args.hash:
            raise KeyError(
                "Requires hash algorithm with the -H flag. Check usage with -h."
            )
        hash_of_file = hash_file(args.file, args.hash)
        hash_report = file_url_report(
            urls["file_report_endpoint"], api_key, hash_type=hash_of_file
        )
        print(
            "Hash algorithm used: {}\nHash of file: {}\n".format(
                args.hash, hash_of_file
            )
        )
        print("Report returned!\nSaving report to {}.json".format(filename))
        with open(filename + ".json", "w") as outfile:
            json.dump(hash_report, outfile, indent=4, sort_keys=True)

    elif args.url:
        url_report = file_url_report(urls["url_report_endpoint"], api_key, url=args.url)
        print("Report returned!\nSaving report to {}.json".format(filename))
        with open(filename + ".json", "w") as outfile:
            json.dump(url_report, outfile, indent=4, sort_keys=True)

    elif args.file_scan:
        if os.stat(args.file_scan).st_size > 33554432:
            print(
                "File size can not be larger than 32 MB. Use /file/scan/upload_url endpoint."
            )
            sys.exit(1)
        scan_file_response = file_scan(urls["file_scan_endpoint"], api_key, args.file_scan)
        print("Scan info saved to file_scan_{}.json".format(filename))
        with open("file_scan_" + filename + ".json", "w") as outfile:
            json.dump(scan_file_response, outfile, indent=4, sort_keys=True)

    elif args.upload_large_file:
        '''
        Does not work with the public API. This API requires additional privileges. 
        Please contact us if you need to upload files bigger than 32MB in size.
        '''
        if os.stat(args.upload_large_file).st_size > 209715200:
            print("File is too large. Max file size limit is 200MB.")
            sys.exit(1)
        elif os.stat(args.upload_large_file).st_size < 33554432:
            print("File size is smaller than 32MB.  Submit file to /file/scan endpoint using -S, --file_scan flag.")
            sys.exit(1)
        else:
            upload_url_response = get_file_upload_url(urls["file_scan_upload_url_endpoint"], api_key,
                                                      args.upload_large_file)
            print("Scan info saved to large_file_scan_{}.json".format(filename))
            with open("large_file_scan_" + filename + ".json", "w") as outfile:
                json.dump(upload_url_response, outfile, indent=4, sort_keys=True)

    # TODO: Accept lists in args and automate running through API
    # TODO: Set delay for requests through API, as to not overload the server and timeout
