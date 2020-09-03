#!/usr/bin/python3

import json
import os
import sys
from datetime import datetime

import requests
from requests.exceptions import HTTPError

import parser
from config.config import auth, urls
from utils.utils import hash_file, create_dir


def file_url_report(endpoint, api_key, url=None, hash_type=None, scan_id=None):
    """
    Retrieves the most recent antivirus report from /file/report or /url/report.  Reports can be looked up with either
    a hash value, url, or scan id.
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
            "Positive Hits: {}\n".format(
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
    Scans a file using the endpoint /file/scan.  File size must be smaller than 32MB.  File can be looked up using the
    returned scan id and submitting it to the /file/report endpoint.
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
            "Verbose Message: {}\n".format(
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
        scan_response = requests.post(upload_url, files=files)
        scan_response.raise_for_status()
    except HTTPError as e:
        print("Exception: {}, {}".format(response.raise_for_status(), str(e)))

    return scan_response.text


def url_scan(endpoint, api_key, url):
    """
    Scans a url using the /url/scan endpoint. Can lookup the report using the returned scan id or url via the
    /url/report endpoint.
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
        response = requests.post(endpoint, params=params, headers=headers)
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
            "Verbose Message: {}\n".format(
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
    :param api_key:  API key for Virus Total.
    :param domain:  Domain name used to retrieve the report.
    :return:  Response from Virus Total Server.
    """
    params = {"apikey": api_key, "domain": domain}
    response = ""
    try:
        # Make request to server for domain report
        response = requests.get(endpoint, params=params)
        # None if response code <200>, HTTPError if otherwise
        response.raise_for_status()
    except HTTPError as e:
        print("Exception: {}, {}".format(response.raise_for_status(), str(e)))
    report = response.json()
    if not report["response_code"] == 1:
        print(report["verbose_msg"])
        sys.exit(1)
    else:
        # return report and print
        print("Verbose Message: {}\n" "Detected URLs: \n".format(report["verbose_msg"]))
        for url in report["detected_urls"]:
            print(json.dumps(url, indent=4, sort_keys=True))

    return report


def ip_address_report(endpoint, api_key, ip):
    """
    :param endpoint:  url for the /domain/report endpoint.
    :param api_key:  API key for Virus Total
    :param ip:  IP address used to retrieve the report.
    :return:  Response from Virus Total Server
    """
    params = {"apikey": api_key, "ip": ip}
    response = ""
    try:
        # Make request to server for ip address report
        response = requests.get(endpoint, params=params)
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
            "Verbose Message: {}\n".format(
                report["asn"],
                report["country"],
                report["verbose_msg"],
            )
        )
    return report


def get_comments(endpoint, api_key, resource, before=None):
    """
    :param endpoint: url for the /comments/get endpoint.
    :param api_key:  API key for Virus Total.
    :param resource: Either an md5/sha1/sha256 hash of the file or the URL itself you want to retrieve.
    :param before:  An optional datetime token that allows you to iterate over all comments on a specific item
                    whenever it has been commented on more than 25 times.
    :return: Response from the server.
    """
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
    # Blank print to make the stdout look a bit cleaner
    print()
    return comments


def put_comments(endpoint, api_key, resource, comment):
    """
    :param endpoint: url for /comments/put endpoint.
    :param api_key: API key for Virus Total API.
    :param comment: Comment to post.
    :param resource: Either an md5/sha1/sha256 hash of the file you want to review or the URL itself that you
                     want to comment on.
    :return: Server response.
    """
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
    args = parser.parser.parse_args()
    filename = str(datetime.now().strftime("%m%d%Y_%H-%M-%S"))

    # Grab the api key from environment variables
    api_key = ""
    try:
        api_key = auth["api_key"]
    except KeyError:
        print("Environment variable does not exist, or can not be accessed.")

    # File argument supplied with no hash algorithm.  Nothing to do here.
    if args.file and not args.hash:
        print(
            "\n**Need to select a hashing algorithm to submit to /file/report endpoint. Try using --hash.**\n"
        )
        parser.parser.print_help(sys.stderr)
        sys.exit(1)

    # Splits the file into chunks and hashes the file to look up using the /file/report endpoint.
    if args.file and args.hash:
        hash_of_file = hash_file(args.file, args.hash)
        print(
            "Hash algorithm used: {}\nHash of file: {}\n".format(
                args.hash, hash_of_file
            )
        )
        hash_report = file_url_report(
            urls["file_report_endpoint"], api_key, hash_type=hash_of_file
        )
        print(
            "Report returned!\nSaving report to results/reports/files/{}.json".format(
                filename
            )
        )
        # Create the results directory tree if it doesn't exist
        create_dir("results/reports/files")
        with open("results/reports/files/" + filename + ".json", "w") as outfile:
            json.dump(hash_report, outfile, indent=4, sort_keys=True)

    # Looks up a report based on the url using the /ur/report endpoint
    elif args.url_report:
        url_report = file_url_report(
            urls["url_report_endpoint"], api_key, url=args.url_report
        )
        print(
            "Report returned!\nSaving report to results/reports/urls/{}.json".format(
                filename
            )
        )
        # Create the results directory tree if it doesn't exist
        create_dir("results/reports/urls")
        with open("results/reports/urls/" + filename + ".json", "w") as outfile:
            json.dump(url_report, outfile, indent=4, sort_keys=True)

    # Scans a file using the /file/scan endpoint. File must be smaller than 32 MB.
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
        # Create the results directory tree if it doesn't exist
        create_dir("results/reports/files")
        with open("results/scans/files/" + filename + ".json", "w") as outfile:
            json.dump(scan_file_response, outfile, indent=4, sort_keys=True)

    # Private endpoint only.  Scans files 32MB - 200MB in size.
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
            # Create the results directory tree if it doesn't exist
            create_dir("results/scans/files")
            with open("results/scans/files/" + filename + ".json", "w") as outfile:
                json.dump(upload_url_response, outfile, indent=4, sort_keys=True)

    # Scans a url with the /url/scan endpoint
    elif args.url_scan:
        url_scan_response = url_scan(urls["url_scan_endpoint"], api_key, args.url_scan)
        print("Scan info saved to results/scans/urls/{}.json".format(filename))
        # Create the results directory tree if it doesn't exist
        create_dir("results/reports/urls")
        with open("results/scans/urls/" + filename + ".json", "w") as outfile:
            json.dump(url_scan_response, outfile, indent=4, sort_keys=True)

    # Submits a scan id to lookup a report using /file/report endpoint.
    elif args.file_scan_id:
        file_report = file_url_report(
            urls["file_report_endpoint"], api_key, args.file_scan_id
        )
        print(
            "Report returned!\nSaving report to results/reports/files/{}.json".format(
                filename
            )
        )
        # Create the results directory tree if it doesn't exist
        create_dir("results/reports/files")
        with open("results/reports/files/" + filename + ".json", "w") as outfile:
            json.dump(file_report, outfile, indent=4, sort_keys=True)

    # Submits a scan id to lookup a report using the /url/report endpoint.
    elif args.url_scan_id:
        url_report = file_url_report(
            urls["url_report_endpoint"], api_key, args.url_scan_id
        )
        print(
            "Report returned!\nSaving report to results/reports/urls/{}.json".format(
                filename
            )
        )
        # Create the results directory tree if it doesn't exist
        create_dir("results/reports/urls")
        with open("results/reports/urls/" + filename + ".json", "w") as outfile:
            json.dump(url_report, outfile, indent=4, sort_keys=True)

    # Looks up a report for a submitted domain name using the /domain/report endpoint.
    elif args.domain:
        domain_response = domain_report(
            urls["domain_report_endpoint"], api_key, args.domain
        )
        print(
            "Report returned!\nSaving report to results/reports/domains-ips/{}.json".format(
                filename
            )
        )
        # Create the results directory tree if it doesn't exist
        create_dir("results/reports/domains-ips/domains")
        with open(
            "results/reports/domains-ips/domains/" + filename + ".json", "w"
        ) as outfile:
            json.dump(domain_response, outfile, indent=4, sort_keys=True)

    # Looks up a report for a submitted ip address using the /ip-address/endpoint.
    elif args.ip:
        ip_report = ip_address_report(
            urls["ip_address_report_endpoint"], api_key, args.ip
        )
        print(
            "Report returned!\nSaving report to results/reports/domains-ips/{}.json".format(
                filename
            )
        )
        # Create the results directory tree if it doesn't exist
        create_dir("results/reports/domains-ips/ips")
        with open(
            "results/reports/domains-ips/ips/" + filename + ".json", "w"
        ) as outfile:
            json.dump(ip_report, outfile, indent=4, sort_keys=True)

    # Looks up the comments for a file or URL using either an md5/sha1/sha256 hash of the file, or a url.
    # Returns 25 comments max.  --before flag can be used to pass the oldest (last in list) comment's date token.
    # Date token must be in the format exactly as it was returned from the prior API call. (e.g.20120404132340).
    elif args.get_comment:
        if args.before:
            comments_response = get_comments(
                urls["get_comments_endpoint"], api_key, args.get_comment, args.before
            )
        else:
            comments_response = get_comments(
                urls["get_comments_endpoint"], api_key, args.get_comment
            )
        print(
            "Report returned!\nSaving report to results/comments/{}.json".format(
                filename
            )
        )
        # Create the results directory tree if it doesn't exist
        create_dir("results/comments")
        with open("results/comments/" + filename + ".json", "w") as outfile:
            json.dump(comments_response, outfile, indent=4, sort_keys=True)

    # Posts a comment for a file or URL. Read the docs for information on commenting.
    # https://support.virustotal.com/hc/en-us/articles/115002146769-Vote-comment
    elif args.put_comment:
        resource, comment = args.put_comment
        put_comments(urls["put_comments_endpoint"], api_key, resource, comment)

    # Parses a csv file of hash values and submits them to /file/report endpoint.
    elif args.csv_file:
        pass

    else:
        if len(sys.argv) == 1:
            parser.parser.print_help(sys.stderr)
            sys.exit(1)

    # TODO: Parse csv files of hash values and submit to /file/report endpoint.
    # TODO: Set delay for requests through API, as to not overload the server and timeout
    # TODO: Allow for args list of files and urls to be passed to file_url_report()
    # TODO: Handle optional scan flag set to 1 for /url/report endpoint
