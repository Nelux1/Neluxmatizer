from cgitb import text
import mechanize
import signal
import requests
from urllib import parse as urlparse
import http.cookiejar
import os, sys
from pynput import keyboard as kb
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
import random
from colorama import Back, Fore, Cursor, init
from time import sleep
from concurrent.futures import ThreadPoolExecutor
init()

wordl=[
    "q=",
    "s=",
    "search=",
    "lang=",
    "keyword=",
    "query=",
    "page=",
    "keywords=",
    "year=",
    "view=",
    "email=",
    "type=",
    "name=",
    "p=",
    "callback=",
    "jsonp=",
    "api_key=",
    "api=",
    "password=",
    "email=",
    "emailto=",
    "token=",
    "username=",
    "csrf_token=",
    "unsubscribe_token=",
    "id=",
    "item=",
    "page_id=",
    "month=",
    "immagine=",
    "list_type=",
    "url=",
    "terms=",
    "categoryid=",
    "key=",
    "l=",
    "begindate=",
    "enddate="
]

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


def xss(l,wordlist,urls_vulnerables,threads):
    print()
    print('---------------------')
    print('\033[1;36m Testing xss: \033[0m') 
    print('---------------------')
    print()
    limp=''
    found=0

    def xss_single(linea,li):
        nonlocal found

        if len(urls_vulnerables) == 0:
         print(Cursor.BACK(50) + Cursor.UP(0) + "\033[46m-_-_-_-_- TESTING -_-_-_-_-\033[0m")
         sleep(2)
         print(Cursor.BACK(50) + Cursor.UP(1) + "\033[1;36m_-_-_-_-_   WAIT  _-_-_-_-_\033[0m")      
        
        sleep(3)
        if 'FUZZ' in linea:
         linea= linea.replace('=FUZZ',f'={li}')
         linea= linea.replace(' ','%20')
        elif '=' and not 'FUZZ' in linea:
          linea= linea.replace('=',f'={li}')
          linea= linea.replace(' ','%20')                         
        try:
          req= requests.get(linea,headers=headers,timeout=50)
          body= str(urlopen(linea).read()).lower()
          if li in body:
             if ".json" in linea:
                 pass
             else:
                 found= found + 1
                 if found == 1:
                     urls_vulnerables.append('\n****************** VULNERABLE TO XSS: *********************\n')
                     print (Cursor.BACK(50) + Cursor.UP(1) + '                                 ')
                 print ('\033[1;32m[+]\033[0m ' + req.url)
                 urls_vulnerables.append(linea)
        except:
         pass        
        linea= linea.replace('%20',' ')
        linea= linea.replace(f'{li}',limp)
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
       for linea in l:
          for li in wordlist:
             executor.submit(xss_single,linea,li)

    if found >= 1:
     print()   
     print (f'\033[1;32m[+] Found [{found}] results vulnerable to XSS\033[0m')
    else:
     print (Cursor.BACK(50) + Cursor.UP(1) + '                                 ')         
     print("\033[1;31m[-] No results found\033[0m")
     print()           
     
def xss_params(l,params,threads):
    print()
    print('---------------------')
    print('\033[1;36m Testing XSS parameters:\033[0m') 
    print('---------------------')
    print()
    found=0
    
    def xssp_single(linea,li):
     for linea in l:   
         for li in wordl:
             if li in linea:
                 found= found + 1
                 if found == 1:
                     params.append('\n****************** PARAMETERS TO XSS: *********************\n') 
                 print('\033[1;32m[+]\033[0m ' + linea)
                 params.append(linea)
         
    with ThreadPoolExecutor(max_workers=threads) as executor:
       for linea in l:
          for li in wordl:
             executor.submit(xssp_single,linea,li)     

    if found >= 1:
     print()
     print (f'\033[1;32m[+] Found [{found}] XSS parameter/s"\033[0m')
    else:
     print("\033[1;31m[-] No results found\033[0m")
     print() 
