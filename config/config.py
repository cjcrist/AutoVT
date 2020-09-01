# config.py

import os

# load api key from environment variables
auth = {
    "api_key": os.environ["VT_API_KEY"],
}

# urls for api endpoints
urls = {
    "file_report_endpoint": "https://www.virustotal.com/vtapi/v2/file/report",
    "url_report_endpoint": "https://www.virustotal.com/vtapi/v2/url/report",
    "file_scan_endpoint": "https://www.virustotal.com/vtapi/v2/file/scan",
    "file_scan_upload_url_endpoint": "https://www.virustotal.com/vtapi/v2/file/scan/upload_url",
    "url_scan_endpoint": "https://www.virustotal.com/vtapi/v2/url/scan",
    "domain_report_endpoint": "https://www.virustotal.com/vtapi/v2/domain/report",
    "ip_address_report_endpoint": "https://www.virustotal.com/vtapi/v2/ip-address/report",
    "get_comments_endpoint": "https://www.virustotal.com/vtapi/v2/comments/get",
    "put_comments_endpoint": "https://www.virustotal.com/vtapi/v2/comments/get",
}
