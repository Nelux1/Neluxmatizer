from fileinput import filename
from socket import timeout
from turtle import back
import mechanize
from urllib import parse as urlparse
import http.cookiejar
import sys
import os
import requests
from urllib.request import urlopen
from parametizer.params import parametizer
from parametizer.core.save_it import save_output 
from scanners.scan_xss import xss
from scanners.scan_idor import idor
from scanners.scan_lfi  import lfi
from scanners.scan_sqli import sqli
from scanners.scan_ssrf import ssrf
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


def scan(U,c,cl,h,x,l,s,i,sr,output,fname,o,vulnerables_urls):
    if 'http://' in U:
        pass
    elif 'https://' in U:
        for linea in U:
         U = U.replace('https://', 'http://')
    else:
        U = 'http://' + U
    try:
        br.open(U, timeout=10.0) #Opens the url
    except URLError as e:
        U = 'https://' + U
        br.open(U)
            
    #forms = br.forms() #Finds all the forms present in webpage

    headers = str(urlopen(U).headers).lower()
  
    # test hsts    
    if h:
        if 'strict-transport-security' not in headers:
            print ('\033[1;32m[+]\033[0m ' + U + ' \033[1;32mNot force HSTS\033[0m')
            vulnerables_urls.append('\n****************** VULNERABLE TO HSTS: *********************\n')
            vulnerables_urls.append(U)      
        else:
            print ('\033[1;31m[-]\033[0m ' + U + ' \033[1;31mHSTS is OK\033[0m')


    # test clickjacking          
    if cl:
        if 'x-frame-options' not in headers:
            if 'content-security-policy' not in headers:
             print ('\033[1;32m[+]\033[0m ' + U + ' \033[1;32mvulnerable to Clickjacking\033[0m')
             vulnerables_urls.append('\n****************** VULNERABLE TO CLICKJACKING: *********************\n')
             vulnerables_urls.append(U)
            else:
             print ('\033[1;31m[-]\033[0m '  + U + ' \033[1;31mis not vulnerable to Clickjacking\033[0m')   
        else:
            print ('\033[1;31m[-]\033[0m '  + U + ' \033[1;31mis not vulnerable to Clickjacking\033[0m')

    # test cors        
    if c:
        headers = {'Origin':'https://evil.com'}
        req= requests.get(U,headers=headers,timeout=30)
        
        headers = str(urlopen(U).headers).lower()

        if 'access-control-allow-origin' in headers:
            if 'https://evil.com' in headers:
                print ('\033[1;32m[+]\033[0m ' + U + ' \033[1;32mis vulnerable to Cors\033[0m')
                vulnerables_urls.append('\n****************** VULNERABLE TO CORS: *********************\n') 
                vulnerables_urls.append(U)              
            else:
                print ('\033[1;31m[-]\033[0m ' + U + ' \033[1;31mis not vulnerable to Cors\033[0m')
        else:
            print ('\033[1;31m[-]\033[0m ' + U + ' \033[1;31mis not vulnerable to Cors\033[0m')
    
    if x:
        uri=[]
        wordlist=['"><script>confirm(1)</script>']
        parametizer(U,output)
        with open(output, "r") as f:
                for i in f.readlines():
                    i = i.strip()
                    if i == "" or i.startswith("#"):
                        continue
                    uri.append(i)            
        print()        
        print('\033[1;33mTest xss for default payload:\033[0m')
        print()        
        xss(uri,wordlist,vulnerables_urls)            
        
    if i:
        uri=[]
        wordlist=['']
        parametizer(U,output) 
        with open(output, "r") as f:
                for i in f.readlines():
                    i = i.strip()
                    if i == "" or i.startswith("#"):
                        continue
                    uri.append(i)            
        print()        
        print('\033[1;33mSearch idor parameters:\033[0m')
        print()
        idor(uri,wordlist,vulnerables_urls)  
              
    #others payloads "%28","%29","%26","%21","'-'","'^'","'*'","'&'"
    if s:
        uri=[]
        wordlist=["'"]
        parametizer(U,output) 
        with open(output, "r") as f:
                for i in f.readlines():
                    i = i.strip()
                    if i == "" or i.startswith("#"):
                        continue
                    uri.append(i)            
        print()        
        print('\033[1;33mTest sql for default payload:\033[0m')
        print()
        sqli(uri,wordlist,vulnerables_urls)     
    

    if sr:
        uri=[]
        wordlist=['']
        parametizer(U,output) 
        with open(output, "r") as f:
                for i in f.readlines():
                    i = i.strip()
                    if i == "" or i.startswith("#"):
                        continue
                    uri.append(i)            
        print()        
        print('\033[1;33Seach SSRF parameters:\033[0m')
        print()
        ssrf(uri,wordlist,vulnerables_urls)

    if l:
        uri=[]
        wordlist=['../../../../../../../../../../../../../../../../../../../../../../etc/passwd']
        parametizer(U,output) 
        with open(output, "r") as f:    
                for i in f.readlines():
                    i = i.strip()
                    if i == "" or i.startswith("#"):
                        continue
                    uri.append(i)            
        print()        
        print('\033[1;33mTest lfi for default payload:\033[0m')
        print()
        lfi(uri,wordlist,vulnerables_urls)

    if o:
     save_output(vulnerables_urls,fname,U)
