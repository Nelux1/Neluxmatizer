import mechanize
from urllib import parse as urlparse
import http.cookiejar
from parametizer.params import parametizer
from scanners.scan import xss
from scanners.scan import lfi
from scanners.scan import sqli
from parametizer.core.save_it import save_output
import sys 
from urllib.request import urlopen
from urllib.error import URLError, HTTPError
from colorama import Back, Fore, init
from scanners.scan_idor import idor
from scanners.scan_lfi import lfi
from scanners.scan_ssrf import ssrf
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

def all_list(l,c,cl,h,x,lf,s,i,sr,output,fname,o,vulnerables_urls):   
     
 for linea in l:
     try:
         print()
         print('---------------------')
         print('\033[1;32m' + linea+':\033[0m')
         print('---------------------')
         print()
         if 'http://' in linea:
             pass
         elif 'https://' in linea:
             for line in linea:
                 linea = linea.replace('https://', 'http://')
         else:
             linea = 'http://' + linea
         try:
             br.open(linea, timeout=10.0) #Opens the url
         except URLError as e:
             linea = 'https://' + linea
             br.open(linea)    
         #forms = br.forms() #Finds all the forms present in webpage

         headers = str(urlopen(linea).headers).lower()

        
         if h:
            if 'strict-transport-security' not in headers:
                print ('\033[1;32m[+]\033[0m ' + linea + ' \033[1;32mNot force HSTS\033[0m')
                vulnerables_urls.append('****************** VULNERABLE TO HSTS: *********************')
                vulnerables_urls.append(linea)      
            else:
                print ('\033[1;31m[-]\033[0m ' + linea + ' \033[1;31mHSTS is OK\033[0m')  
         
         if cl:
            if 'x-frame-options' not in headers:
                if 'content-security-policy' not in headers:
                 print ('\033[1;32m[+]\033[0m ' + linea + ' \033[1;32mvulnerable to Clickjacking\033[0m')
                 vulnerables_urls.append('****************** VULNERABLE TO CLICKJACKING: *********************')
                 vulnerables_urls.append(linea)
                else:
                 print ('\033[1;31m[-]\033[0m '  + linea + ' \033[1;31mis not vulnerable to Clickjacking\033[0m')
            else:
                 print ('\033[1;31m[-]\033[0m '  + linea + ' \033[1;31mis not vulnerable to Clickjacking\033[0m')
         
         if c:
                br.addheaders = [('User-agent', 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1'),
         ('Accept','text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'), ('Accept-Encoding','br'), ('Origin','https://evil.com')]

                if 'access-control-allow-origin' in headers:
                    if 'https://evil.com' in headers:
                        print ('\033[1;32m[+]\033[0m ' + linea + ' \033[1;32mis vulnerable to Cors\033[0m')
                        vulnerables_urls.append('****************** VULNERABLE TO CORS: *********************') 
                        vulnerables_urls.append(linea)                           
                    else:
                        print ('\033[1;31m[-]\033[0m ' + linea + ' \033[1;31mis not vulnerable to Cors\033[0m')
                else:
                    print ('\033[1;31m[-]\033[0m ' + linea + ' \033[1;31mis not vulnerable to Cors\033[0m')
     except:
         continue
     try:    
         if x:
            uri=[]
            wordlist=['"><script>confirm(1)</script>']
            try:
                parametizer(linea,output)
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
            except: 
                  continue
     except:
        continue
     try:    
         if s:
             uri=[]
             wordlist=["'"]   
             try:
                 parametizer(linea,output)
                 with open(output, "r") as f:
                     for i in f.readlines():
                         i = i.strip()
                         if i == "" or i.startswith("#"):
                             continue
                         uri.append(i)            
                 print()        
                 print('\033[1;33mTest sqli for default payload:\033[0m')
                 print()        
                 sqli(uri,wordlist,vulnerables_urls)           
             except: 
                  continue
     except:
         continue    
     try:    
         if i:
             uri=[]
             wordlist=['']   
             try:
                 parametizer(linea,output)
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
             except: 
                  continue
     except:
        continue
     try:    
         if sr:
             uri=[]
             wordlist=['']   
             try:
                 parametizer(linea,output)
                 with open(output, "r") as f:
                     for i in f.readlines():
                         i = i.strip()
                         if i == "" or i.startswith("#"):
                             continue
                         uri.append(i)            
                 print()        
                 print('\033[1;33mSearch SSRF parameters:\033[0m')
                 print()        
                 ssrf(uri,wordlist,vulnerables_urls)           
             except: 
                  continue
     except:
         continue        
     try:    
         if lf:
            uri=[]
            wordlist=['../../../../../../../../../../../../../../../../../../../../../../etc/passwd']   
            try:
                parametizer(linea,output)
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
            except: 
                  continue
     except:
         continue
     if o:
         save_output(vulnerables_urls,fname,linea)    
           
