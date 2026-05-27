# aws.py

```sh
# Download the script
curl -O https://raw.githubusercontent.com/andreif/aws.py/main/aws.py

# Only allow your current user to access it
chmod 0700 aws.py

# Move it to other executables so it can be run as `aws.py ...`
sudo mv aws.py /usr/local/bin/

# Replace aws-vault
cd /usr/local/bin/
sudo mv aws-vault aws-vault.old
sudo ln -s aws.py aws-vault

# Enable module import so that PyCharm etc. is able to index it
sudo ln -s /usr/local/bin/aws.py /Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/lib/python3.9/
```

## TODO

- Import aws client and other utils, like jaml, request, gather_with_concurrency
- Show notifications
- Store encrypted to mitigate simple memory scans
