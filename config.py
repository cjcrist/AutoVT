import os

auth = {
    "vt_api_key": os.environ.get('VT_API_KEY'),
}

urls = {
    "file_api": "https://www.virustotal.com/vtapi/v2/file/report",
    "url_api": "https://www.virustotal.com/vtapi/v2/url/report",
}
