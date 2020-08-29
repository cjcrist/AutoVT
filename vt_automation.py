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

    response = ""
    try:
        # Make request to server to retrieve report.
        response = requests.get(endpoint, params)
        # None if response code <200>, HTTPError if otherwise
        response.raise_for_status()
    # Print the response code and Exception
    except HTTPError as e:
        print("Exception: {}, {}".format(response.raise_for_status(), str(e)))
    report = response.json()
    # Check results of scan returned from API
    if not report["response_code"] == 1:
        print(report["verbose_msg"])
        sys.exit(0)
    else:
        # Prints some results and returns the dictionary of PSPs.  Can Do whatever here.
        scans_dict = report["scans"]
        print(
            "Scan ID: {}\n"
            "Resource: {}\n"
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
    params = {"apikey": api_key}
    files = {"file": (file, open(file, "rb"))}

    response = ""
    try:
        # Make request to server to scan file
        response = requests.post(endpoint, files=files, params=params)
        # None if response code <200>, HTTPError if otherwise
        response.raise_for_status()
    # Print the response code and Exception
    except HTTPError as e:
        print("Exception: {}, {}".format(response.raise_for_status(), str(e)))
    scan = response.json()
    # Check results of scan returned from API
    if not scan["response_code"] == 1:
        print(scan["verbose_msg"])
        sys.exit(0)
    else:
        # Print response from the scan
        print(
            "Scan ID: {}\n"
            "Resource: {}\n"
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
    response = ""
    try:
        # Fetches a special url to submit file to server
        response = requests.post(endpoint, params=params)
        # None if response code <200>, HTTPError if otherwise
        response.raise_for_status()
        # Print the response code and Exception
    except HTTPError as e:
        print("Exception: {}, {}".format(response.raise_for_status(), str(e)))
    upload_url = response.json()
    files = {"file": (file, open(file, "rb"))}
    # Scan using the upload url
    scan_response = ""
    try:
        scan_response = requests.post(upload_url, files)
        scan_response.raise_for_status()
    except HTTPError as e:
        print("Status Code: {}, Exception: {}".format(response.status_code, str(e)))

    return scan_response.text


def url_scan(endpoint, api_key, url):
    """
    :param endpoint: url for /url/scan endpoint
    :param api_key: API key for Virus Total
    :param url: url to scan
    :return: response from Virus Total server
    """
    params = {
        "apikey": api_key,
        "url": url,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    response = ""
    try:
        # Post request to server to scan url
        response = requests.post(endpoint, data=params, headers=headers)
        # None if response code <200>, HTTPError if otherwise
        response.raise_for_status()
    except HTTPError as e:
        print("Exception: {}, {}".format(response.raise_for_status(), str(e)))
    # Check results of scan returned from API
    scan = response.json()
    if not scan["response_code"] == 1:
        print(scan["verbose_msg"])
        sys.exit(0)
    else:
        # Print response from the scan
        print(
            "Scan ID: {}\n"
            "Scan Date: {}\n"
            "Url Scanned: {}\n"
            "Link to Scan: {}\n"
            "Verbose Message: {}".format(
                scan["scan_id"],
                scan["scan_date"],
                scan["url"],
                scan["permalink"],
                scan["verbose_msg"],
            )
        )

    return scan


def domain_report(endpoint, api_key, domain):
    """
    :param endpoint:  url for the /domain/report endpoint.
    :param api_key:  API key for Virus Total
    :param domain:  Domain name to be scanned
    :return:  Response from Virus Total Server
    """
    params = {"apikey": api_key, "domain": domain}
    response = ""
    try:
        # Make request to server for domain report
        response = requests.get(endpoint, data=params)
        # None if response code <200>, HTTPError if otherwise
        response.raise_for_status()
    except HTTPError as e:
        print("Exception: {}, {}".format(response.raise_for_status(), str(e)))
    return response.json()


def ip_address_report(endpoint, api_key, ip):
    """
    :param endpoint:  url for the /domain/report endpoint.
    :param api_key:  API key for Virus Total
    :param ip:  IP address to be scanned
    :return:  Response from Virus Total Server
    """
    params = {"apikey": api_key, "ip": ip}
    response = ""
    try:
        # Make request to server for ip address report
        response = requests.get(endpoint, data=params)
        # None if response code <200>, HTTPError if otherwise
        response.raise_for_status()
    except HTTPError as e:
        print("Exception: {}, {}".format(response.raise_for_status(), str(e)))
    report = response.json()
    if not report["response_code"] == 1:
        print(report["verbose_msg"])
        sys.exit(0)
    else:
        # Print response from the server
        print(
            "ASN: {}\n"
            "Country: {}\n"
            "Verbose Message: {}".format(
                report["asn"],
                report["country"],
                report["verbose_msg"],
            )
        )
    return report


def get_comments(endpoint, api_key, hash_type=None, url=None, before=None):
    """
    :param endpoint: url for the /comments/get endpoint.
    :param api_key:  API key for Virus Total.
    :param hash_type:Comments can be retrieved by hash values (md5, sha1, sha256).
    :param url:     Comments can be retrieved by URL.
    :param before:  An optional datetime token that allows you to iterate over all comments on a specific item
                    whenever it has been commented on more than 25 times.
    :return: Response from the server.
    """
    if hash_type:
        resource = hash_type
    else:
        resource = url

    if before:
        date_token = before
    else:
        date_token = ""

    params = {"apikey": api_key, "resource": resource, "before": date_token}
    response = ""
    try:
        # Make request to server to get comment
        response = requests.get(endpoint, params=params)
        # None if response code <200>, HTTPError if otherwise
        response.raise_for_status()
    except HTTPError as e:
        print("Exception: {}, {}".format(response.raise_for_status(), str(e)))
    comments = response.json()
    if not comments["response_code"] == 1:
        print(comments["verbose_msg"])
        sys.exit(0)
    else:
        # Print response from the server
        print(
            "Resource: {}\n"
            "Verbose Message: {}\n".format(
                comments["resource"], comments["verbose_msg"]
            )
        )
    for comment in comments["comments"]:
        print(json.dumps(comment, indent=4, sort_keys=True))
    return comments


def put_comments(endpoint, api_key, comment, hash_type=None, url=None):
    """
    :param endpoint: url for /comments/put endpoint.
    :param api_key: API key for Virus Total API.
    :param comment: Comment to upload
    :param hash_type: Optional lookup resource by hash of file to review.
    :param url: Optional lookup resource by url to comment on.
    :return: Server response.
    """
    if hash_type:
        resource = hash_type
    else:
        resource = url

    params = {"apikey": api_key, "resource": resource, "comment": comment}
    response = ""
    try:
        # Make request to server to post comment
        response = requests.post(endpoint, params=params)
        # None if response code <200>, HTTPError if otherwise
        response.raise_for_status()
    except HTTPError as e:
        print("Exception: {}, {}".format(response.raise_for_status(), str(e)))
    comment_response = response.json()
    if not comment_response["response_code"] == 1:
        print(comment_response["verbose_msg"])
        sys.exit(1)
    else:
        print(comment_response["verbose_msg"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="This program interacts with the Virus Total public API, and is "
        "intended to work on Linux. \nBefore using this tool, you first need to obtain an "
        "API key, and store in environment variables:\n"
        "$export VT_API_KEY = 'your-api-key'.\n"
        "For more information: https://developers.virustotal.com/reference#getting-started"
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
        "--url_report",
        metavar="URL_Report",
        type=str,
        required=False,
        help="Retrieves the most recent antivirus report of the URL from /url/report endpoint.",
    )
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
        "--upload_large_file",
        metavar="Upload_Large_File",
        type=str,
        required=False,
        help="For files 32MB-200MB in size. Generates a special upload url from /file/scan/upload_url endpoint, and "
        "submits the file to be scanned. Does not work with the public API. This API requires additional "
        "privileges. Please contact us if you need to upload files bigger than 32MB in size.",
    )
    parser.add_argument(
        "-us",
        "--url_scan",
        metavar="URL_Scan",
        type=str,
        required=False,
        help="Submits a url to be scanned using the /url/scan endpoint.",
    )
    # parser.add_argument(
    # 'F',
    # '--file_list',
    # metavar='File_List',
    # FileType=str,
    # required=False,
    # help='Parses a file of hashes to be submitted to /file/report endpoint.'
    # )

    args = parser.parse_args()
    filename = str(datetime.now().strftime("%m%d%Y_%H-%M-%S"))

    # Grab the api key from environment variables
    api_key = ""
    try:
        api_key = auth["api_key"]
    except KeyError:
        print("Environment variable does not exist, or can not be accessed.")

    if args.file:
        print(
            "\n**Need to select a hashing algorithm to submit to /file/report endpoint. Try using --hash.**\n"
        )
        parser.print_help(sys.stderr)
        sys.exit(1)
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
        print(
            "Report returned!\nSaving report to results/reports/files{}.json".format(
                filename
            )
        )
        with open("results/reports/files/" + filename + ".json", "w") as outfile:
            json.dump(hash_report, outfile, indent=4, sort_keys=True)

    elif args.url_report:
        url_report = file_url_report(urls["url_report_endpoint"], api_key, url=args.url)
        print(
            "Report returned!\nSaving report to results/reports/urls/{}.json".format(
                filename
            )
        )
        with open("results/reports/urls/" + filename + ".json", "w") as outfile:
            json.dump(url_report, outfile, indent=4, sort_keys=True)

    elif args.file_scan:
        if os.stat(args.file_scan).st_size > 33554432:
            print(
                "File size can not be larger than 32 MB. Use /file/scan/upload_url endpoint."
            )
            sys.exit(1)
        scan_file_response = file_scan(
            urls["file_scan_endpoint"], api_key, args.file_scan
        )
        print("Scan info saved to results/scans/files/{}.json".format(filename))
        with open("results/scans/files/" + filename + ".json", "w") as outfile:
            json.dump(scan_file_response, outfile, indent=4, sort_keys=True)

    elif args.upload_large_file:
        """
        Does not work with the public API. This API requires additional privileges.
        Please contact us if you need to upload files bigger than 32MB in size.
        """
        if os.stat(args.upload_large_file).st_size > 209715200:
            print("File is too large. Max file size limit is 200MB.")
            sys.exit(1)
        elif os.stat(args.upload_large_file).st_size < 33554432:
            print(
                "File size is smaller than 32MB.  Submit file to /file/scan endpoint using -S, --file_scan flag."
            )
            sys.exit(1)
        else:
            upload_url_response = get_file_upload_url(
                urls["file_scan_upload_url_endpoint"], api_key, args.upload_large_file
            )
            print("Scan info saved to results/scans/files/{}.json".format(filename))
            with open("results/scans/files/" + filename + ".json", "w") as outfile:
                json.dump(upload_url_response, outfile, indent=4, sort_keys=True)

    elif args.url_scan:
        url_scan_response = url_scan(urls["url_scan_endpoint"], api_key, args.url_scan)
        print("Scan info saved to results/scans/urls/{}.json".format(filename))
        with open("results/scans/urls/" + filename + ".json", "w") as outfile:
            json.dump(url_scan_response, outfile, indent=4, sort_keys=True)

    else:
        if len(sys.argv) == 1:
            parser.print_help(sys.stderr)
            sys.exit(1)

    # TODO: Accept lists in args and automate running through API
    # TODO: Set delay for requests through API, as to not overload the server and timeout
