#!/usr/bin/env python3
#
import signal
import os
from os import system
from urllib import parse as urlparse
import sys
import argparse
from colorama import Back, Fore, init
from scanners.scan_lista import all_list
from parametizer.core.save_it import save_output
from parametizer.interrupt import signal_handler
from colorama import Back, Fore, Cursor, init
import time 
start_time = time.time()
init()

print("\033[1;36m"+'''

    @@@@     @@@@ 
    @@@@@    @@@@ @@@@@@@@@@  @@@@      @@@@    @@@ @@@@   @@@@
    @@@@ @@  @@@@ @@@@        @@@@      @@@@    @@@   @@   @@                     
    @@@@  @@ @@@@ @@@@@@@@    @@@@      @@@@    @@@     @@@     MATIZER
    @@@@    @@@@@ @@@@        @@@@      @@@@    @@@   @@   @@   
    @@@@     @@@@ @@@@@@@@@@  @@@@@@@@  @@@@@@@@@@@ @@@@   @@@@ 

                                 by Marcos Suarez for pentesters v6.7

'''+ '\033[0;m')

print("\x1b[1;35m"+'EXIT PROGRAM WITH CRTL+C'+ '\033[0;m')
print()

parser = argparse.ArgumentParser(prog="neluxmatizer.py")
def parse_excepciones(value):
    return value.split(",")

parser.add_argument("-u","--url",
                    dest="url",
                    help="select url to scan",
                    action='store')
parser.add_argument("-a","--all",
                    dest="all",
                    help="Check URL all vulnerabilities.",
                    action= 'store_true' )                    
parser.add_argument("-cors",
                    dest="cors",
                    help="Check Cors vulnerability.",
                    action= 'store_true' )
parser.add_argument("-v",
                    dest="version",
                    help="Check version.",
                    action= 'store_true' )
parser.add_argument("-click",
                    dest="click",
                    help="Check Clickjacking vulnerability.",
                    action= 'store_true' )
parser.add_argument("-l",
                    dest="usedlist",
                    help="Check a list of URLs.",
                    action= 'store' )
parser.add_argument("-w",
                    dest="word",
                    help="wordlist of payloads",
                    action= 'store' )
parser.add_argument("-t",
                    dest="threads",
                    help="threads",
                    action= 'store' )
parser.add_argument("-xss",
                    dest="xss",
                    help="Check XSS vulnerability or params.",
                    action= 'store_true' )
parser.add_argument("-xxe",
                    dest="xxe",
                    help="Check XXE vulnerability.",
                    action= 'store_true' )
parser.add_argument("-lfi",
                    dest="lfi",
                    help="Check LFI vulnerability or params.",
                    action= 'store_true' )
parser.add_argument("-crlf",
                    dest="crlf",
                    help="Check CRLF vulnerability.",
                    action= 'store_true' )                     
parser.add_argument("-sql",
                    dest="sql",
                    help="Check SQL vulnerability or params.",
                    action= 'store_true' )
parser.add_argument("-idor",
                    dest="idor",
                    help="Check IDOR params.",
                    action= 'store_true' )
parser.add_argument("-rce",
                    dest="rce",
                    help="Check RCE vulnerability or params.",
                    action= 'store_true' )
parser.add_argument("-redirect",
                    dest="redirect",
                    help="Check OPENREDIRECT vulnerability or params.",
                    action= 'store_true' )                                                                                
parser.add_argument("-ssrf",
                    dest="ssrf",
                    help="Check SSRF vulnerability or params.",
                    action= 'store_true' )
parser.add_argument("-ssti",
                    dest="ssti",
                    help="Check SSTI vulnerability or params.",
                    action= 'store_true' )
parser.add_argument("-E",
                    dest="exceptions",
                    help="Except vulneranility to scan",
                    type=parse_excepciones,
                    action='store')
parser.add_argument("-only-params","-op",
                     dest="params", 
                     help = 'save params for fuzzing')
parser.add_argument("-o",
                     dest="output", 
                     help = 'Output file name')
                                                                              
args = parser.parse_args()                                                         


       
def selector():    
    output= os.path.join('output','param.txt')
    output2= os.path.join('output','urls.txt')
    url = []
    wordlist=[]
    urls_vulnerables=[]
    urls_params=[]
    threads=30
    fname= os.path.join('output','urls_vulnerables.txt')
    c,cl,cr,x,xe,l,s,i,r,rc,sr,sst,o,op=False,False,False,False,False,False,False,False,False,False,False,False,False,False 
    if args.version:
         print('version 6.7')
         print('Check the current version at https://github.com/Nelux1/Neluxmatizer.git')
    if args.url:
         url.append(str(args.url))                
    if args.usedlist:
         with open(args.usedlist, "r") as f:
             for q in f.readlines():
                 q = q.strip()
                 if q == "" or q.startswith("#"):
                     continue
                 url.append(q)                  
    if args.cors:
         c=True
    if args.click:
         cl=True
    if args.crlf:
         cr=True  
    if args.idor:
         i=True
    if args.rce:
         rc=True
    if args.redirect:
         r=True        
    if args.ssrf:
         sr=True 
    if args.ssti:
         sst=True
    if args.xxe:
         xe=True                             
    if args.all:
         c,cl,cr,x,xe,l,s,i,r,rc,sr,sst=True,True,True,True,True,True,True,True,True,True,True,True 
         if args.exceptions:          
           exceptions = args.exceptions
           if "cors" in exceptions:
                    c = False
                    print(exceptions)
           if "click" in exceptions :
                    cl = False
           if "crlf" in exceptions :
                    cr = False
           if "xss" in exceptions:
                    x = False 
           if "xxe" in exceptions:
                    xe = False
           if "sql" in exceptions:
                    s = False
           if "rce" in exceptions:
                    rc = False
           if "ssrf" in exceptions:
                    sr = False
           if "ssti" in exceptions :
                   sst = False
           if "redirect" in exceptions:
                    r = False
           if "lfi" in exceptions:
                    l = False                                                                                                                                                               
    if args.params:
         c,cl,h=False,False,False
         fname= os.path.join(args.params)
         op=True   
    if args.output:
         fname= os.path.join(args.output)
         o=True
    if args.xss and not args.word:
         x=True
    if args.sql and not args.word:
         s=True         
    if args.lfi and not args.word:
         l=True                                       
    if not args.word:        
      all_list(url,c,cl,cr,x,xe,l,s,i,r,rc,sr,sst,output,output2,fname,o,urls_vulnerables,op,urls_params,threads,wordlist)        
    if args.word:
         with open(args.word, "r") as f:
             for i in f.readlines():
                 i = i.strip()
                 if i == "" or i.startswith("#"):
                     continue
                 wordlist.append(i)             
         if args.xss:
           x=True                        
           all_list(url,c,cl,cr,x,xe,l,s,i,r,rc,sr,sst,output,output2,fname,o,urls_vulnerables,op,urls_params,threads,wordlist)
         if args.lfi:
           l=True
           all_list(url,c,cl,cr,x,xe,l,s,i,r,rc,sr,sst,output,output2,fname,o,urls_vulnerables,op,urls_params,threads,wordlist)              
         if args.sql:
           s=True
           all_list(url,c,cl,cr,x,xe,l,s,i,r,rc,sr,sst,output,output2,fname,o,urls_vulnerables,op,urls_params,threads,wordlist)
         if args.output:
           save_output(urls_vulnerables,fname,l)
     
    if os.path.exists(output):
        os.remove(output)
    if os.path.exists(output2):
        os.remove(output2)
        
     
if len(sys.argv) <= 1:
    print('\n%s -h for help.' % (sys.argv[0]))
    exit(0)



if __name__ == "__main__":
    signal.signal(signal.SIGINT,signal_handler)
    try:
        selector()
    except KeyboardInterrupt:
        exit(0)


