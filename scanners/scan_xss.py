from cgitb import text
import mechanize
import requests
from urllib import parse as urlparse
import http.cookiejar
import os
import sys
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
import random


user_agents = [
 "Mozilla/5.0 (X11; U; Linux i686; it-IT; rv:1.9.0.2) Gecko/2008092313 Ubuntu/9.25 (jaunty) Firefox/3.8",
 "Mozilla/5.0 (X11; Linux i686; rv:2.0b3pre) Gecko/20100731 Firefox/4.0b3pre",
 "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.8.1.6)",
 "Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en)",
 "Mozilla/3.01 (Macintosh; PPC)",
 "Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.9)",  
 "Mozilla/5.0 (X11; U; Linux 2.4.2-2 i586; en-US; m18) Gecko/20010131 Netscape6/6.01",  
 "Opera/8.00 (Windows NT 5.1; U; en)",  
 "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.19 (KHTML, like Gecko) Chrome/0.2.153.1 Safari/525.19"
]

user_agent = random.choice (user_agents)
headers = {'User-Agent': user_agent}

def xss(l,wordlist,urls_vulnerables):
    print()
    print('---------------------')
    print('\033[1;36m Testing xss: \033[0m') 
    print('---------------------')
    print()
    limp=''
    found=0
    for linea in l:
        for li in wordlist:
         if 'FUZZ' in linea:
                linea= linea.replace('=FUZZ',f'={li}')
                linea= linea.replace(' ','%20')
         elif '=' and not 'FUZZ' in linea:
                linea= linea.replace('=',f'={li}')
                linea= linea.replace(' ','%20')                         
         try:
             req= requests.get(linea,timeout=50)
             body= str(urlopen(linea).read()).lower()
             if li in body:
                 found= found + 1
                 if found == 1:
                    urls_vulnerables.append('\n****************** VULNERABLE TO XSS: *********************\n')
                 print ('\033[1;32m[+]\033[0m ' + linea)
                 urls_vulnerables.append(linea)
         except:
             continue
         linea= linea.replace('%20',' ')
         linea= linea.replace(f'{li}',limp)
    if found >= 1:
     print()   
     print (f'\033[1;32m[+] Found [{found}] results vulnerable to XSS\033[0m')
    else:
     print("\033[1;31m[-] No results found\033[0m")            
