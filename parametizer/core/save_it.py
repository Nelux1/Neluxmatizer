import os
import errno
import time
start_time = time.time()


def _work_dir():
    return os.environ.get("NELUXMATIZER_WORKDIR") or os.path.abspath(os.getcwd())


def _resolve_out(path):
    path = os.path.expanduser(path)
    if os.path.isabs(path):
        return path
    return os.path.join(_work_dir(), path)


def save_func(final_urls , outfile , domain):
    if outfile:
        if "/" in outfile:
            filename = _resolve_out(outfile)
        else:
            filename = _resolve_out(os.path.join("output", outfile))
    else:
        filename = _resolve_out(os.path.join("output", f"{domain}.txt"))
    
    if os.path.exists(filename):
        os.remove(filename)

    if not os.path.exists(os.path.dirname(filename)):
        try:
            os.makedirs(os.path.dirname(filename))
        except OSError as exc: 
            if exc.errno != errno.EEXIST:
                raise
    
    
    for i in final_urls:
        with open(filename, "a" , encoding="utf-8") as f:
            f.write(i+"\n")

def save_output(urls_vulnerables,nfile,domain_vuln, append_mode=False):

    if nfile:
        if "/" in nfile:
            filename = _resolve_out(nfile)
        else:
            filename = _resolve_out(os.path.join("output", nfile))
    else:
        filename = _resolve_out(os.path.join("output", f"{domain_vuln}.txt"))
    
    # Solo borrar si no es modo append
    if os.path.exists(filename) and not append_mode:
        os.remove(filename)

    if not os.path.exists(os.path.dirname(filename)):
        try:
            os.makedirs(os.path.dirname(filename))
        except OSError as exc: 
            if exc.errno != errno.EEXIST:
                raise
    
    for i in urls_vulnerables:
        with open(filename, "a" , encoding="utf-8") as f:
         if i.strip():
             f.write(i+"\n")
    
