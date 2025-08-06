from hashlib import md5
from tqdm import *

for n in tqdm(range(2**28)):
    if md5(str(n).encode() + b'HOxVshMQUWlsUnxFWSyu').hexdigest() == "b3dc7ef78fafda1edffed8f0dfe7eb41":
        print(n)