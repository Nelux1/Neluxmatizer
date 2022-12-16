import re 


def param_extract(response, holder):

    ''' 
    Function to extract URLs with parameters
    regexp : r'.*?:\/\/.*\?.*\=[^$]'
    
    '''

    parsed = list(set(re.findall(r'.*?:\/\/.*\?.*\=[^$]' , response)))
    final_uris = []
        
    for i in parsed:
        delim = i.find('=')
        second_delim = i.find('=', i.find('=') + 1)
        final_uris.append((i[:delim+1] + holder))
    
    return list(set(final_uris))

def param_extract2(response):

    ''' 
    Function to extract URLs with parameters
    regexp : r'.*?:\/\/.*\?.*\=[^$]'
    
    '''

    parsed = list(set(re.findall(r'.*?:\/\/.*\?.*\=[^$]' , response)))
    final_uris = []
        
    for i in parsed:
        #delim = i.find('=')
        #second_delim = i.find('=', i.find('=') + 1)
        final_uris.append(i)
    
    return list(set(final_uris))
