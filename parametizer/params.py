from parametizer.core import requester
from parametizer.core import extractor
from parametizer.core import save_it
from urllib.parse import unquote
import requests,re
from urllib.error import URLError, HTTPError
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from colorama import Fore,Back,Cursor, init
import signal
import os
import sys
import time 
from concurrent.futures import ThreadPoolExecutor
start_time = time.time()
init()

    
def parametizer(url,output,threads):
    #print()   
    if os.name == 'nt':
      os.system('cls')
   
    def par_single(url):  
     url = f"https://web.archive.org/cdx/search/cdx?url=*.{url}/*&output=txt&fl=original&collapse=urlkey&page=/"    
     retry = True
     retries = 0
     try:
       while retry == True and retries <= int(3):
             response, retry = requester.connector(url)
             retry = retry
             retries   += 1
     except:
       retry= False
       retries=3
       response=''
                 
     if response == False:
         return 
       
     response = unquote(response)
     final_uris = extractor.param_extract(response , holder='FUZZ') 
     save_it.save_func(final_uris , output , url)

     if len(final_uris) == 0:
       print()
       print(Cursor.BACK(50) + Cursor.UP(1) + '\033[1;31m[-]\033[0m ' + ' Not Parameters Found' )


    with ThreadPoolExecutor(max_workers=threads) as executor:
             executor.submit(par_single,url)        
    

def parametizer2(url, output,threads):
    
    print()
    print('\033[1;33mSearch parameters:\n\033[0m')
    
    def par_single2(url):  
     url = f"https://web.archive.org/cdx/search/cdx?url=*.{url}/*&output=txt&fl=original&collapse=urlkey&page=/"    
     retry = True
     retries = 0
     try:
       while retry == True and retries <= int(3):
             response, retry = requester.connector(url)
             retry = retry
             retries   += 1
     except:
       retry= False
       retries=3
       response=''
                 
     if response == False:
         return 
       
     response = unquote(response)
     final_uris = extractor.param_extract2(response)
     save_it.save_output(final_uris , output , url)

     if len(final_uris) == 0:
       print()
       print(Cursor.BACK(50) + Cursor.UP(1) + '\033[1;31m[-]\033[0m ' + ' Not Parameters Found' )
     if len(final_uris) >= 1:    
        print(f"\033[1;32m[+] Total urls found : {len(final_uris)}\033[1;31m")

    with ThreadPoolExecutor(max_workers=threads) as executor:
             executor.submit(par_single2,url)

def parametizer3(url,output2,threads):

  def obtener_endpoints(url):
  
      try:
        req=requests.get(url,timeout=10.0) #Opens the url
      except URLError as e:
          for line in url:
           url = line.replace('http://', 'https://')
          try:    
            req=requests.get(url,timeout=10.0)
          except URLError:        
            print(f'\033[1;31{req.status_code} [?] open Url Error\033[0m')
            return
          # Enviar una solicitud GET a la URL
  
      # Analizar el contenido HTML de la respuesta
      soup = BeautifulSoup(req.content, 'html.parser')
      url = f"https://web.archive.org/cdx/search/cdx?url=*.{url}/*&output=txt&fl=original&collapse=urlkey&page=/"    
      retry = True
      retries = 0
      try:
       while retry == True and retries <= int(3):
             response, retry = requester.connector(url)
             retry = retry
             retries   += 1
      except:
       retry= False
       retries=3
       response=''
                 
      if response == False:
         return     
      # Obtener el dominio de la URL base
      dominio_base = urlparse(url).netloc
      
      # Encontrar todos los enlaces en la página
      enlaces = soup.find_all('a')
      
      # Obtener los endpoints y separar los específicos de la URL base de los externos
      endpoints_base = []
      response = unquote(response)
      final_uris = extractor.param_extract2(response)
      
      for enlace in enlaces:
          
          endpoint = enlace.get('href')
          endpoint_url = urljoin(url, endpoint)  # Construir la URL completa del endpoint
          
          # Verificar si el endpoint pertenece al mismo dominio que la URL base
          if urlparse(endpoint_url).netloc == dominio_base:
              endpoints_base.append(endpoint_url)
      endpoints = [uri for uri in final_uris if dominio_base]

      endpoints_base.extend(endpoints)
      save_it.save_output(endpoints_base,output2,url)

      if len(endpoints_base) == 0:
        print()
        print(Cursor.BACK(50) + Cursor.UP(1) + '\033[1;31m[-]\033[0m ' + ' Not endpoints Found' )


# Ejemplo de uso
  with ThreadPoolExecutor(max_workers=threads) as executor:
    executor.submit(obtener_endpoints,url)


  
