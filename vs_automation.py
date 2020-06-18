#!/usr/bin/python 3

import argparse
import hashlib
import sys

import requests
from requests.exceptions import HTTPError

import config as cfg


def vt_report(output, endpoint, api_key, url=None, md5=None):
    """
    Runs a scan and returns data to generate a report.  Can be used to run any type of scan, with the correct
    parameters set.
    :param output: output file to be written too.
    :param endpoint: URL for type of scan being ran
    :param api_key: API key for virus total
    :param url: If running url scan, set url = url, else leave None
    :param md5: If running md5 hash scan, set md5 = hash_file(file) when calling function, else leave None
    :return: Currently returns some data from scan.  Can be changed to return anything.
    """

    # Check to see if md5 hash or url provided in params
    if md5:
        report_type = md5
    else:
        report_type = url
    params = {
        'apikey': api_key,
        'resource': report_type,
    }
    # response, scan = ''
    try:
        # Get response from server
        response = requests.get(endpoint, params)
        # None if response code <200>, HTTPError if otherwise
        if response.raise_for_status() is not None:
            raise HTTPError
        scan = response.json()
    # Print the response code and Exception
    except HTTPError as e:
        print("Status Code: {}, Exception: {}".format(response.status_code, str(e)))
    # Check results of scan returned from API
    if scan['response_code'] == 0:
        return [output, ['verbose_msg']]
    else:
        # Prints some results and returns the dictionary of PSPs.  Can Do whatever here.
        scans_dict = scan['scans']
        print("Output: {}\n"
              "URL Scanned: {}\n"
              "Scan Date: {}\n"
              "Link to Scan: {}\n"
              "Total Scans: {} \n"
              "Positive Hits: {}".format(output, scan['resource'], scan['scan_date'], scan['permalink'],
                                         scan['total'], scan['positives']))
        return scans_dict


def chunk_size(size, text):
    """
    Generates a block of data, incrementing till the EOF
    :param size: Size of block in bytes
    :param text: Text of file being chunked
    :return: A chunk of data of the size of the block, or smaller if at EOF
    """
    start = 0
    while start < len(text):
        chunk = text[start:start + size]
        yield chunk
        start += size
    return


def hash_file(file):
    """
    Generates a MD% Hash for file, once it has been chunked and added to the buffer.
    :param file: File passed in to be hashed
    :return: MD5 hash of file
    """
    # sets a block size limit for the hasher
    block_size = 4000
    # MD5 hash buffer for each block of data held in memory
    hash_buffer = hashlib.md5()

    try:
        # Read in file
        with open(file, 'rb') as binFile:
            # For each chunk of data returned from chunk_size
            for chunk in chunk_size(block_size, binFile.read()):
                # Add it to the buffer
                hash_buffer.update(chunk)
            # Run a md5 hash on the entire file in the buffer, and return
            return hash_buffer.hexdigest().encode('utf-8')
    except MemoryError as e:
        # If MemoryError, virtual memory depleted.  May need to add more memory to VM, or choose a smaller file.
        print("Exception: {}".format(str(e)))
        sys.exit(1)


if __name__ == "__main__":
    # parser = argparse.ArgumentParser(description="Automate the task of running hashes and urls through Virus Total.")
    # parser.add_argument('-f', '--file', type=str, required=False, help="File")
    # parser.add_argument('-H', '--hash', type=str, required=False, help="Hash Value(s)")
    # parser.add_argument('-o', '--output', required=False, help="Output File Location - Ex: /On/Your/Desktop/output.txt")
    # parser.add_argument('-uR', '--urlReport', type=str, required=False, help="URL")
    # args = parser.parse_args()

    test_file = "random.txt"
    url = "http://www.megacorpone.com"

    # if args.hash:
    #     file = open(args.output, 'a+')
    #     file.write('Below is the identified hash report.\n\n')
    #     file.close()
    #     hash_scan = vt_report("Doing a hash scan", cfg.urls['file_api'], cfg.auth['vt_api_key'],
    #                           md5=hash_file(test_file))
    # elif args.urlReport:
    #     file = open(args.output, 'a+')
    #     file.write('Below is the identified url report.\n\n')
    #     file.close()
    #     url_scan = vt_report("Doing a url scan", cfg.urls['url_api'], cfg.auth['vt_api_key'],
    #                          url="http://www.need-to-change.com")
    # elif args.file:
    #     file = open(args.output, 'a+')
    #     file.write('Below is the identified file report.\n\n')
    #     file.close()
    #     file_scan = vt_report("Doing a hash scan", cfg.urls['file_api'], cfg.auth['vt_api_key'],
    #                           md5=hash_file(test_file))

    # Example of a hash scan, without passing url param
    hash_scan = vt_report("Doing a hash scan", cfg.urls['file_api'], cfg.auth['vt_api_key'], md5=hash_file(test_file))

    # Example of a url_scan, without passing md5 param
    url_scan = vt_report("Doing a url scan", cfg.urls['url_api'], cfg.auth['vt_api_key'],
                         url=url)

    print(url_scan)

    # TODO: Write a main function to handle logic for parsing argv parameters.
    # TODO: Figure out needs for returning data from scan, and how to store it.
    # TODO: Accept lists in args and automate running through API
    # TODO: Set delay for requests through API, as to not overload the server and timeout
    # TODO: Add to config file to run metrics and graphs with API
    # TODO: Display metrics and graphs as option in args
