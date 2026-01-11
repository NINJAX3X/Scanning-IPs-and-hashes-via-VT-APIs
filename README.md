# Scanning-IPs-and-hashes-via-VT-APIs
Run the script using Python to scan multiple IPs and hashes via VT APIs

Run the script to do the same via VT Public/Premium API (Need to get the VT API Public key by creating an account on VT)
 
Note:   - Input file of all the IPs that needs to be scanned should be in .txt format and one IP per line - should be on the same path from where you run the script or else need to edit the script to the path where the IPs             txt files exists
        - Input IP filename should be "ips" with .txt as extension as in the script or else you can change in the script based on your ease of use
 
Also, when using the Public API key - the public API of VT has rate limit set so it is limited for use - Limited to 500 requests per day and 4 requests per minute. So in a day only 250 IPs/hashes can be reanalyzed + checking its reputation. If you want to just check the reputation of the IP/hash then you can do it for 500 IPs/hashes (Need to change the script - comment out the function where reanalyzing takes place).
