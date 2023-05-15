from pprint import pprint
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
import requests
from urllib import parse as urlparse
from parametizer.progress import update_progress
import http.cookiejar
import os, sys
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
import random
from colorama import Back, Fore, Cursor, init
from time import sleep
from concurrent.futures import ThreadPoolExecutor
init()

wordl=[
    "q=",
    "s=",
    "search=",
    "lang=",
    "keyword=",
    "query=",
    "page=",
    "keywords=",
    "year=",
    "view=",
    "email=",
    "type=",
    "name=",
    "p=",
    "callback=",
    "jsonp=",
    "api_key=",
    "api=",
    "password=",
    "email=",
    "emailto=",
    "token=",
    "username=",
    "csrf_token=",
    "unsubscribe_token=",
    "id=",
    "item=",
    "page_id=",
    "month=",
    "immagine=",
    "list_type=",
    "url=",
    "terms=",
    "categoryid=",
    "key=",
    "l=",
    "begindate=",
    "enddate="
]

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
headers = {'User-Agent': user_agent}


def xss(l,wordlist,urls_vulnerables,threads):
    print()
    print('---------------------')
    print('\033[1;36m Testing xss: \033[0m') 
    print('---------------------')
    print()
    limp=''
    found=0
    total = len(l)    
    progress=0

    def xss_single(linea,li):

        nonlocal found,progress
        
        
        if 'FUZZ' in linea:
         linea= linea.replace('=FUZZ',f'={li}')
         linea= linea.replace(' ','%20')
        elif '=' and not 'FUZZ' in linea:
          linea= linea.replace('=',f'={li}')
          linea= linea.replace(' ','%20')                         
        try:
          req= requests.get(linea,headers=headers,timeout=50)
          body= str(urlopen(linea).read()).lower()
          if li in body:
             if ".json" in linea:
                 pass
             else:
                 found= found + 1
                 if found == 1:
                     urls_vulnerables.append('\n****************** VULNERABLE TO XSS: *********************\n')
                 print ('\033[1;32m[+]\033[0m ' + req.url, end='\n')
                 urls_vulnerables.append(linea)
          progress+=1
          update_progress(progress, total)           
        except:
         progress+=1
         update_progress(progress, total)  
         pass        
        linea= linea.replace('%20',' ')
        linea= linea.replace(f'{li}',limp)

        
    with ThreadPoolExecutor(max_workers=threads) as executor:                      
       for linea in l:
          for li in wordlist:
             executor.submit(xss_single,linea,li)

    if found >=1:
     print()
     print (Cursor.BACK(50) + Cursor.UP(1) + f'\033[1;32m[+] Found [{found}] results vulnerable to XSS\033[0m')
    else:
     print (Cursor.BACK(50) + Cursor.UP(1) + '      '*80)        
     print(Cursor.BACK(50) + Cursor.UP(1) + "\033[1;31m[-] No results found\033[0m")
     print()           


def xss_forms(l,wordlist,urls_vulnerables):
        print()
        print('---------------------')
        print('\033[1;36m Testing xss in forms: \033[0m') 
        print('---------------------')
        print()
        f=0
        p=0
        total = len(l)    
        try:
             for linea in l:
                for li in wordlist:
                    if scan_xss(linea,li):
                        f+=1                    
                        if f == 1:
                            urls_vulnerables.append('\n****************** VULNERABLE TO XSS FORMS: *********************\n')
                        urls_vulnerables.append(linea)
                p+=1
                update_progress(p, total)                 
        except:
            p+=1
            update_progress(p, total)       
            pass

        if f >=1:  
           print (f'\033[1;32m[+] Found [{f}] results vulnerable to XSS\033[0m')
        else:
            print (Cursor.BACK(50) + Cursor.UP(1) + '      '*80)        
            print(Cursor.BACK(50) + Cursor.UP(1) + "\033[1;31m[-] No results found\033[0m")
            print()           
     
def xss_params(l,params,threads):
    print()
    print('---------------------')
    print('\033[1;36m Testing XSS parameters:\033[0m') 
    print('---------------------')
    print()
    found=0
    
    def xssp_single(linea,li):
     for linea in l:   
         for li in wordl:
             if li in linea:
                 found= found + 1
                 if found == 1:
                     params.append('\n****************** PARAMETERS TO XSS: *********************\n') 
                 print('\033[1;32m[+]\033[0m ' + linea)
                 params.append(linea)
         
    with ThreadPoolExecutor(max_workers=threads) as executor:
       for linea in l:
          for li in wordl:
             executor.submit(xssp_single,linea,li)     

    if found >= 1:
     print()
     print (f'\033[1;32m[+] Found [{found}] XSS parameter/s"\033[0m')
    else:
     print("\033[1;31m[-] No results found\033[0m")
     print() 
       
def get_all_forms(url):
       
     """Given a `url`, it returns all forms from the HTML content"""    
     soup = bs(requests.get(url).content, "html.parser")
     return soup.find_all("form")
    
def get_form_details(form):
        """
        This function extracts all possible useful information about an HTML `form`
        """
        details = {}
        # get the form action (target url)
        action = form.attrs.get("action", "").lower()
        # get the form method (POST, GET, etc.)
        method = form.attrs.get("method", "get").lower()
        # get all the input details such as type and name
        inputs = []
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            inputs.append({"type": input_type, "name": input_name})
        # put everything to the resulting dictionary
        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
        return details
    
def submit_form(form_details, url, value):
        """
        Submits a form given in `form_details`
        Params:
            form_details (list): a dictionary that contain form information
            url (str): the original URL that contain that form
            value (str): this will be replaced to all text and search inputs
        Returns the HTTP Response after form submission
        """
        # construct the full URL (if the url provided in action is relative)
        target_url = urljoin(url, form_details["action"])
        # get the inputs
        inputs = form_details["inputs"]
        data = {}
        for input in inputs:
            # replace all text and search values with `value`
            if input["type"] == "text" or input["type"] == "search":
                input["value"] = value
            input_name = input.get("name")
            input_value = input.get("value")
            if input_name and input_value:
                # if input name and value are not None, 
                # then add them to the data of form submission
                data[input_name] = input_value
        if form_details["method"] == "post":
            return requests.post(target_url, data=data)
        else:
            # GET request
            return requests.get(target_url, params=data)
        
def scan_xss(url,payload):
        """
        Given a `url`, it prints all XSS vulnerable forms and 
        returns True if any is vulnerable, False otherwise
        """
        # get all the forms from the URL
        forms = get_all_forms(url)
        js_script = payload
        # returning value
        is_vulnerable = False
        # iterate over all forms
        for form in forms:
            form_details = get_form_details(form)
            content = submit_form(form_details, url, js_script).content.decode()
            if js_script in content:
                if "https://web.archive.org/" in url:
                    pass
                else:
                        print(f"\033[1;32m[+]\033[0m XSS Detected on {url}")
                        print(f"\x1b[1;35m[*]\033[0;m Form details:")
                        pprint(form_details)
                        print()
                        is_vulnerable = True
                    # won't break because we want to print available vulnerable forms
        return is_vulnerable    
