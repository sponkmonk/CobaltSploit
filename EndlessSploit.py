import os
import base64

while True:
    for filename in os.listdir('servers'):
        try:
            filename = filename.replace("'", "")
            base64_bytes = filename.encode("ascii")
            sample_string_bytes = base64.b64decode(base64_bytes)
            sample_string = sample_string_bytes.decode("ascii")
            os.system("python3 exploit.py --url " + sample_string + " --use_tor true --publish_to_threatfox true --max_hits 100")
        except KeyboardInterrupt: # Breaking here so the program can end
            exit()
        except Exception as e:
            print(str(e))
