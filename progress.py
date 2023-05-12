
def update_progress(progress, total):
    percentage = min(progress / total * 100, 100)  # Asegurar que el porcentaje no supere el 100%
    bar_length = 30
    filled_length = int(bar_length * (progress / total))
    bar = '█' * filled_length + '-' * (bar_length - filled_length)
    if progress == total:
        print(f'\033[1;36m[{bar.ljust(bar_length)}] {percentage:.1f}%\033[0m', end='\r')
    elif percentage < 100:
        print(f'\033[1;36m[{bar.ljust(bar_length)}] {percentage:.1f}%\033[0m', end='\r')
