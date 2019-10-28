###
# albinolobster@ubuntu:~$ python3 mt_www_version.py 
# crc: 1660362373
# size: 43765
# version: 6.0
#
# albinolobster@ubuntu:~$ python3 mt_www_version.py 
# crc: 2855787042
# size: 66364
# version: 6.45.3
###

import re
import csv
import sys
import argparse
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

top_parser = argparse.ArgumentParser(description='Download /webfig/roteros.info from RouterOS 6.0+ web interface')
top_parser.add_argument('-c', '--csv', action="store", dest="csv", required=True, help="The list of IP addresses and ports to check")
args = top_parser.parse_args()

info_regex = re.compile("^{ crc: ([0-9]+), size: ([0-9]+), name: \"roteros.jg\",.*version: \"([0-9\\.a-z]+)\" },")

with open(args.csv) as csv_file:
	csv_reader = csv.reader(csv_file, delimiter=",")

	count = 0
	error = 0
	for row in csv_reader:
		print("\r" + str(count), file=sys.stderr, end="")
		sys.stderr.flush()

		handler = "http://"
		if (row[1] == "443"):
			handler = "https://"
		req = Request(handler + row[0] + ":" + row[1] + "/webfig/roteros.info")
		try:
			response = urlopen(req, timeout=3)
			json = response.read().decode("utf-8")
		except HTTPError as e:
			error = error + 1
		except URLError as e:
			error = error + 1
		except:
			error = error + 1
		else:
			
			result = info_regex.match(json)
			if result != None:
				print(row[0], end=",")
				print(row[1], end=",")
				print(result[1], end=",")
				print(result[2], end=",")
				print(result[3])
				sys.stdout.flush()

		count = count + 1

print("\nDone!", file=sys.stderr)

