# Parser.py
import argparse

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
    "--file",
    metavar="File",
    type=str,
    required=False,
    help="File to be hashed and submitted to /file/report endpoint. Set hash type with --hash md5/sha1/sh256.",
)
parser.add_argument(
    "--hash",
    metavar="Set File Hash",
    type=str,
    required=False,
    choices=["md5", "sha1", "sha256"],
    help="Hashes a file and submits the hash [md5, sha1, sha256] to /file/report. Used in conjunction with --file.",
)
parser.add_argument(
    "--url_report",
    metavar="URL Report",
    type=str,
    required=False,
    help="Retrieves the most recent antivirus report of the URL from /url/report endpoint.",
)
parser.add_argument(
    "--file_scan",
    metavar="File Scan",
    required=False,
    help="Submit a file to be scanned to the /file/scan endpoint. Will return a scan id. Max file size is 32MB."
    "If file is larger than 32MB, use /file/scan/upload.",
)
parser.add_argument(
    "--url_scan",
    metavar="URL Scan",
    type=str,
    required=False,
    help="Submits a url to be scanned using the /url/scan endpoint.",
)
parser.add_argument(
    "--file_scan_id",
    metavar="File Scan ID",
    type=str,
    required=False,
    help="Retrieves the most recent antivirus report from /file/report endpoint using the scan_id returned "
    "from /file/scan endpoint.",
)
parser.add_argument(
    "--url_scan_id",
    metavar="URL Scan ID",
    type=str,
    required=False,
    help="Retrieves the most recent antivirus report form /url/report endpoint using the scan_id returned "
    "from /url/scan endpoint.",
)
parser.add_argument(
    "--csv_file",
    metavar="CSV File",
    type=argparse.FileType("r"),
    required=False,
    help="Parses a csv file of hash values and submits them to the /file/report endpoint.  This could take some "
    "time with a public API key since the bandwidth is 4 requests per minute.",
)
parser.add_argument(
    "--upload_large_file",
    metavar="Upload Large File",
    type=str,
    required=False,
    help="For files 32MB-200MB in size. Generates a special upload url from /file/scan/upload_url endpoint, and "
    "submits the file to be scanned. Does not work with the public API. This API requires additional "
    "privileges. Please contact us if you need to upload files bigger than 32MB in size.",
)
parser.add_argument(
    "--domain",
    metavar="Domain Report",
    type=str,
    required=False,
    help="Retrieves a domain report using the /domain/report endpoint.",
)
parser.add_argument(
    "--ip",
    metavar="IP Address Report",
    type=str,
    required=False,
    help="Retrieves an IP Address report using the /ip_address/report endpoint.",
)
parser.add_argument(
    "--get_comment",
    metavar="Get Comment",
    type=str,
    required=False,
    help="Either an md5/sha1/sha256 hash of the file or the URL itself you want to retrieve. Use the optional "
    "--before flag to retrieve comments using the comment's date token.",
)
parser.add_argument(
    "--before",
    type=str,
    required=False,
    help="A datetime token that allows you to iterate over all comments on a specific item whenever it has been "
    "commented on more than 25 times. Must be exactly in the same format that was returned by your previous "
    "API call (e.g. 20120404132340).",
)
parser.add_argument(
    "--put_comment",
    type=str,
    required=False,
    nargs=2,
    metavar=("(resource,", "comment)"),
    help="Resource: Either an md5/sha1/sha256 hash of the file you want to review or the URL itself that you "
    "want to comment on.  Comment: Comment to post.",
)
