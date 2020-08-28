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
}
