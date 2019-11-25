#!/usr/bin/env python

__author__ = "Josh Stroschein"
__version__ = "0.0.1"
__maintainer__ = "Josh Stroschein"

import sys, os, requests, optparse, datetime, json, time, random

api_key = "<YOUR API KEY>"

throttle = 20

api_base_url = "https://www.hybrid-analysis.com/api/v2/"
user_agent = "Falcon Sandbox"
terms_url = "search/terms"
feeds_url = "feed/latest"
download_url = "overview/"

def setup_args():

    parser = optparse.OptionParser()

    parser.add_option('-q', '--query',
    action="store", dest="query",
    help="The type of search - feed, terms, hash", default="terms")

    parser.add_option('-f', '--filetype',
    action="store", dest="filetype",
    help="File type to search for - see HA docs for full list", default="doc") 

    parser.add_option('-d', '--directory',
    action="store", dest="directory",
    help="Location to save the downloaded samples", default="samples")

    parser.add_option('-l', '--limit',
    action="store", dest="limit",
    help="Limit number of results to download", default=200)

    parser.add_option('-p', '--parameters',
    action="store", dest="parameters",
    help="Search filters as defined by API docs, in the form of 'key:value,key:value'", default="") 

    parser.add_option('-s', '--shuffle',
    action="store", dest="shuffle",
    help="Shuffle the list of returned results before downloading - values are y or n", default="n")

    parser.add_option('-v', '--verbose',
    action="store", dest="verbose",
    help="Print results of key aspects of the script, such as total results found, number downloaded, et cetera", default="n") 

    return parser.parse_args()


def download_sample(download_url, headers, save_directory, sample_sha256):
    download = requests.get(download_url, headers = headers)

    if not os.path.exists(save_directory):
        os.makedirs(save_directory)

    with open(save_directory + "/" + sample_sha256 + ".gz", "wb") as file:
        file.write(download.content)

def main(argv):

    options, args = setup_args() 
    parameters = {}
    headers = {
        "accept":"application/json",
        "Content-Type":"application/x-www-form-urlencoded",
        "User-Agent":user_agent,
        "api-key": api_key
    }

    if options.parameters:
        filters = options.parameters.split(",")
        for filter in filters:
            key,value = filter.split(":")
            parameters[key] = value

    download_count = 0

    if options.query == "terms":

        headers["accept"] = "application/json"

        parameters["filetype"] = options.filetype 
        parameters["date_to"] = '{0:%Y-%m-%d %H:%M}'.format(datetime.datetime.now())

        resp = requests.post(api_base_url + terms_url, data = parameters, headers = headers)

        results = json.loads(resp.text)

        if options.verbose == "y":
            print("[*] Found " + str(results["count"]) + " results")

        results = results["result"]

        if options.shuffle == "y":
            random.shuffle(results)

        for result in results:

            headers["Content-Type"] = "application/gzip"

            if result["verdict"] == "malicious":
                if options.verbose == "y":
                    print("[*] Downloading sample - " + str(result["sha256"]))

                download_sample(api_base_url + download_url + result["sha256"] + "/sample", 
                headers, 
                options.directory,
                result["sha256"])

                download_count = download_count + 1

                time.sleep(throttle)

            if download_count >= int(options.limit):
                if options.verbose == "y":
                    print("[!] Download limit reached")
                break

    elif options.query == "feed":

        headers["accept"] = "application/json"

        resp = requests.get(api_base_url + feeds_url, headers = headers)

        results = json.loads(resp.text)

        if options.verbose == "y":
            print("[*] Found " + str(results["count"]) + " results")

        results = results["data"]
        
        if options.shuffle == "y":
            random.shuffle(results)

        for result in results:

            headers["Content-Type"] = "application/gzip"

            if result["interesting"] == True:

                if options.verbose == "y":
                    print("[*] Downloading sample - " + str(result["sha256"]))

                download_sample(api_base_url + download_url + result["sha256"] + "/sample", 
                headers,
                options.directory,
                result["sha256"])

                download_count = download_count + 1

                time.sleep(throttle)

            if download_count >= int(options.limit):
                if options.verbose == "y":
                    print("[!] Download limit reached")
                break

    if options.verbose == "y":
        print("[*] Downloaded " + str(download_count) + " samples")

if __name__ == '__main__':
	main(sys.argv[1:])