#!/usr/bin/env python3
#
import signal
import os
from os import system
from urllib import parse as urlparse
import sys
import argparse
from colorama import Back, Fore, init
from parametizer.params import parametizer
from scanners.scan_sqli import sqli
from scanners.scan_xss import xss
from scanners.scan_lista import all_list
from scanners.scan_lfi import lfi
from scanners.scan_ssti import ssti
from parametizer.core.save_it import save_output
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

                                 by Marcos Suarez for pentesters v4.0.0

'''+ '\033[0;m')

print("\x1b[1;35m"+'EXIT PROGRAM WITH CRTL+C'+ '\033[0;m')
print()
parser = argparse.ArgumentParser(prog="neluxmatizer.py")

parser.add_argument("-u","--url",
                    dest="url",
                    help="select url to scan",
                    action='store')
parser.add_argument("-a","--all",
                    dest="all",
                    help="Check URL all vulnerabilities.",
                    action= 'store_true' )                    
parser.add_argument("--cors",
                    dest="cors",
                    help="Check Cors vulnerability.",
                    action= 'store_true' )
parser.add_argument("--hsts",
                    dest="hsts",
                    help="Check hsts header vulnerability.",
                    action= 'store_true' )
parser.add_argument("--click",
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
parser.add_argument("--xss",
                    dest="xss",
                    help="Check XSS vulnerability.",
                    action= 'store_true' )
parser.add_argument("--lfi",
                    dest="lfi",
                    help="Check LFI vulnerability.",
                    action= 'store_true' )                    
parser.add_argument("--sql",
                    dest="sql",
                    help="Check SQL vulnerability.",
                    action= 'store_true' )
parser.add_argument("--idor",
                    dest="idor",
                    help="Check IDOR parameters.",
                    action= 'store_true' )
parser.add_argument("--rce",
                    dest="rce",
                    help="Check RCE vulnerability.",
                    action= 'store_true' )
parser.add_argument("--redirect",
                    dest="redirect",
                    help="Check OPENREDIRECT vulnerability.",
                    action= 'store_true' )                                                                                
parser.add_argument("--ssrf",
                    dest="ssrf",
                    help="Check SSRF vulnerability.",
                    action= 'store_true' )
parser.add_argument("--ssti",
                    dest="ssti",
                    help="Check SSTI vulnerability.",
                    action= 'store_true' )                  
parser.add_argument("--only-params","-op",
                     dest="params", 
                     help = 'save params for fuzzing')
parser.add_argument("-o",
                     dest="output", 
                     help = 'Output file name')
                                                                              
args = parser.parse_args()                                                         


def signal_handler(signal, frame):
     print()
     print(Cursor.BACK(50) + Cursor.UP(0) + '                                                     ')
     print("\x1b[1;35m"+'NOT CLOSE?'+ '\033[0;m'+ '  ----->  '+ "\x1b[1;31m"+ ' PRESS CTRL+C AGAIN'+ '\033[0;m')
     sys.exit(0)
    
    
def selector():
    signal.signal(signal.SIGINT,signal_handler)
    output= os.path.join('output','domain.txt')
    url = []
    wordlist=[]
    urls_vulnerables=[]
    urls_params=[]
    threads=30
    fname= os.path.join('output','urls_vulnerables.txt')
    c,cl,h,x,l,s,i,r,rc,sr,sst,o,op=False,False,False,False,False,False,False,False,False,False,False,False,False 
    if args.url:
         url.append(str(args.url))                
    elif args.usedlist:
         with open(args.usedlist, "r") as f:
             for q in f.readlines():
                 q = q.strip()
                 if q == "" or q.startswith("#"):
                     continue
                 url.append(q)                  
    if args.hsts: 
         h=True
    if args.cors:
         c=True
    if args.click:
         cl=True
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
    if args.all:
         c,cl,h,x,l,s,i,r,rc,sr,sst,=True,True,True,True,True,True,True,True,True,True,True 
    if args.params:
         c,cl,h=False,False,False
    if args.output:
         fname= os.path.join(args.output)
         o=True
    if args.params:
         fname= os.path.join(args.params)
         op=True            
    if args.xss and not args.word:
         x=True
    if args.sql and not args.word:
         s=True         
    if args.lfi and not args.word:
         l=True                                       
    if not args.word:        
     all_list(url,c,cl,h,x,l,s,i,r,rc,sr,sst,output,fname,o,urls_vulnerables,op,urls_params,threads)        
    if args.word:
         with open(args.word, "r") as f:
             for i in f.readlines():
                 i = i.strip()
                 if i == "" or i.startswith("#"):
                     continue
                 wordlist.append(i)
             for l in url:
                 uri=[]
                 print()
                 print('---------------------')
                 print('\033[1;32m' +l+':\033[0m')
                 print('---------------------')
                 print()        
                 parametizer(l,output,threads)
                 try: 
                     with open(output, "r") as f:
                         for i in f.readlines():
                             i = i.strip()
                             if i == "" or i.startswith("#"):
                                 continue
                             uri.append(i)
                             save=True
                 except:
                     save=False               
                 if args.xss:                        
                     xss(uri,wordlist,urls_vulnerables,threads)
                 if args.lfi:
                     lfi(uri,wordlist,urls_vulnerables,threads)                 
                 if args.sql:
                     sqli(uri,wordlist,urls_vulnerables,threads)
                 if args.output:
                     if save:
                         save_output(urls_vulnerables,fname,l)

     
if len(sys.argv) <= 1:
    print('\n%s -h for help.' % (sys.argv[0]))
    exit(0)



if __name__ == "__main__":
    try:
        selector()
    except KeyboardInterrupt:
        pass

