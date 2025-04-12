import re

def param_extract(response, holder):
    
    r''' 
    Function to extract URLs with parameters and replace values with a holder string.
    r'.*?:\/\/.*\?.*=.*'
    '''

    
    parsed = list(set(re.findall(r'.*?:\/\/.*\?.*=.*', response)))
    final_uris = []
        
    for i in parsed:
        delim = i.find('=')
        final_uris.append(i[:delim + 1] + holder)
    
    return list(set(final_uris))

def param_extract2(response):
    
    r''' 
    Function to extract full URLs with parameters without modification.
    r'.*?:\/\/.*\?.*=.*'
    '''

    parsed = list(set(re.findall(r'.*?:\/\/.*\?.*=.*', response)))
    final_uris = []

    for i in parsed:
        final_uris.append(i)
    
    return list(set(final_uris))

