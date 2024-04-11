import requests
import random
import time

def connector(url):
    result = False
    user_agent_list = [
   #Most common desktop useragents
     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.1",
     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.3",
     "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.",
     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.1",
     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Safari/605.1.1",
     "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.",
     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.3",
     "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.3",
     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.",                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            
     "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/117.",
     "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36 OPR/95.0.0.",
     "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.3",
     "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.3",                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   
]

user_agent = random.choice(user_agent_list)
    
        

    try:
        # control request headers in here
            headers = {'User-Agent': user_agent}
            response = requests.get(url,headers=headers ,timeout=100)
            result = response.text
            retry = False
            response.raise_for_status()    
    except requests.exceptions.ConnectionError as e:
            retry = False
            print (f"\u001b[31;1mCan not connect to server. Check your internet connection. (Status code: {response.status_code})\u001b[0m")
    except requests.exceptions.Timeout as e:
            retry = True
            print (f"\u001b[31;1mOOPS!! Timeout Error. Retrying in 2 seconds. Status code: {response.status_code}\u001b[0m")
            time.sleep(2)
    except requests.exceptions.HTTPError as err:
            retry = True

            print (f"\u001b[31;1m {err}. Retrying in 5 seconds. Status code: {response.status_code}\u001b[0m")
            time.sleep(5)
            response=True

    except requests.exceptions.RequestException as e:
            retry = True
            print (f"\u001b[31;1m {e} Can not get target information. Status code: {response.status_code}\u001b[0m")
            pass
    except KeyboardInterrupt as k:
            retry = False
            print ("\u001b[31;1mInterrupted by user\u001b[0m")
            raise SystemExit(k)
    finally:
            return result, retry
