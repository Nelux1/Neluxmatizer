from cgitb import text
import mechanize
import requests
from urllib import parse as urlparse
import http.cookiejar
import os
import sys
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from colorama import Back, Fore, init

init()

#Stuff related to Mechanize browser module
br = mechanize.Browser() #Shortening the call by assigning it to a varaible "br"
# set cookies
cookies = http.cookiejar.LWPCookieJar()
br.set_cookiejar(cookies)
# Mechanize settings
br.set_handle_equiv(True)
br.set_handle_redirect(True)
br.set_handle_referer(True)
br.set_handle_robots(False)
br.set_debug_http(False)
br.set_debug_responses(False)
br.set_debug_redirects(False)
br.set_handle_refresh(mechanize._http.HTTPRefreshProcessor(), max_time = 1)
br.addheaders = [('User-agent', 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1'),
('Accept','text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'), ('Accept-Encoding','br')]



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
         linea= linea.replace(f'={li}',limp)
    if found >= 1:
     print()   
     print (f'\033[1;32m[+] Found [{found}] results vulnerable to XSS\033[0m')
    else:
     print("\033[1;31m[-] No results found\033[0m")            