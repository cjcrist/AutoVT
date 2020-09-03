## AutoVT - A Virus Total Automation Tool

This is a quick and dirty project to automate some tasks with Virus Total's public API, and is being developed on Ubuntu Linux 20.04 using Python 3.8.2.    

Before using this tool, you first need to sign up and acquire an API key from Virus Total. More information on getting an API key, and documents for the Virus Total API can be found [here](https://developers.virustotal.com/reference#getting-started).

Once you have an API key, you can load it into environment variables like this:

```
export VT_API_KEY="Your API KEY"
```

The API key variable is stored in **config/config.py**. If you are using virtualenv, there is an issue where some global environment variables do not load.  I found this to be an issue when launching an editor, like PyCharm.  To get around this, either launch the editor from the terminal, or edit the local environment variables in PyCharm:
	
```
File>Settings>Python Console>Environment Variables. 
```

### Results
Scan/Report responses from the server are saved in the results directory of the project.  You can edit the save location by changing the **create_dir()** function in utils.py.

```
utils>utils.py>create_dir()
```

<p align="center">
	<img src="/images/results.png">
</p>

### API Endpoints and Usage:
* To start, you can display the usage by running the program with no arguments, or with the -h flag.  A screenshot of the usage display is at the bottom of this section.

```
python3 autovt.py -h
```

#### [/file/report/](https://developers.virustotal.com/reference#file-report)
* Retrieves a file scan report by a supplied MD5, SHA-1, or SHA-256 hash of a file. You can also look up a report by a scan\_id returned byt the **/file/scan** endpoint.
* To check if a local file has already been reported on Virus Total, you can use the --file flag to pass a file, and the --hash  flag to choose the hashing algorithm.

```
python3 autovt.py --file /path/to/file --hash sha256
```

* You can also lookup the report of a previously scanned file.

```
python3 autovt.py --file_scan_id 919f7c754991dfd5bd17f195dcda393baa9180309fa7d20b9c3fe0f303a3acfc-1599110772
```

#### [/file/scan](https://developers.virustotal.com/reference#file-scan)
* This endpoint allows you to send a file for scanning with Virus Total, and returns a report with a scan id.
* Max file size is 32MB.
* Public API limit is 4 requests per minute.

```
python3 autovt.py --file_scan /path/to/file
```

#### [/file/scan/upload\_url](https://developers.virustotal.com/reference#file-scan-upload-url)
* This endpoint is for use with a Private API key only, and is currently untested.
* Creates a request to generate a special upload url, and submits the file to be uploaded.
* Max file size is 200MB.

```
python3 autovt.py --upload_large_file /path/to/file
```

#### [/url/report](https://developers.virustotal.com/reference#url-report)
* Retrieves a URL scan report from Virus Total.

```
python3 autovt.py --url_report url-to-lookup
```

* You can also lookup the report of a previously scanned url by using the scan id returned from /url/scan.

```
python3 autovt.py --url_scan_id 1db0ad7dbcec0676710ea0eaacd35d5e471d3e11944d53bcbd31f0cbd11bce31-1599111923
```

#### [/url/scan](https://developers.virustotal.com/reference#url-scan)
* Scans a URL with Virus Total.

```
python3 autovt.py --url_scan url-to-scan
```

#### [/domain/report](https://developers.virustotal.com/reference#domain-report)
* Retrieves a report on a domain name from Virus Total.

```
python3 autovt.py --domain domain-name
```

#### [/ip-address/report](https://developers.virustotal.com/reference#ip-address-report)
* Retrieves a report for an IP address from Virus Total.

```
python3 autovt.py --ip ip-address
```

#### [/comments/get](https://developers.virustotal.com/reference#comments-get)
* Retrieves the comments for a specific file or URL.
* This flag takes either an MD5/SHA1/SHA256 hash value, or the URL itself.

The server answers with up to 25 comments for specific report.  If there are less than 25 comments, then all of the comments have been returned.  If there are 25 comments returned, then you can use the optional --before flag to list a comment's date token, which should be the oldest (last in the list) comment.  The date token must be exact, in the form (20200405132340).

```
python3 autovt.py --get_comment b1e10cab59f21754b9d9e1dce41b16d7

or 

python3 autovt.py --get_comment b1e10cab59f21754b9d9e1dce41b16d7 --before 20200405132340
```

#### [/comment/put](https://developers.virustotal.com/reference#comments-put)
* Allows you to post a comment for a file or URL.
* This flag takes 2 paramaters (resource, comment)
* resource: Either an MD5, SHA1, or SHA255 hash of the file you want to review, or the URL to the report.
* comment: The comment you want to post.

Currently this flag only allows for a short comment passed in as an argument.  This will be updated to allow a more detailed comment to be passed in via a file.  Review the documentation for guidlines on commenting [here](https://support.virustotal.com/hc/en-us/articles/115002146769-Vote-comment).

```
python3 autovt.py --put_comment "This comment is just a test of the API endpoint."
```

<p align="center">
	<img src="/images/usage.png">
</p>


## Development
This project is still in development, and is currently being worked on.

I would *love* to hear what you think about **AutoVT** on the [issues page](https://github.com/cjcrist/AutoVT/issues). 

Make pull requests, report bugs, suggest ideas or features, and discuss **AutoVT**.

## TODO's
As this project is still in development, there are a few features and upgrades to be made.

* Add functionality to pass in hash values, scan ids, or urls via a csv file to look up reports in Virus Total.
* Add functionality to pass multiple arguments via the command line to scan files/urls and retrieve reports.
* Add option to scan url if no report is found.
* Load balance requests to API, as public API keys are limited to 4 request per minute.
