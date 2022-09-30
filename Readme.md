# Tool for mass testing ZeroLogon vulnerability CVE-2020-1472
 
![proof]('proof.png' "Proof")


## Steps to procedure

For using this tool you need a hosts file with the `ip adress and hostname separated by comma`

*   Hosts file sample

``` 
1.1.1.1    ,      WIN-6641554161U 
1.1.1.1    ,           SERVERDATA 
1.1.1.1    ,           SERVER2012 
1.1.1.1    ,                 DC01 
1.1.1.1    ,               SERVER 
```

You can get this type of file with valid ip adress following the next steps

*   Scanning with nmap using the next parameters <br>
``` 
nmap -p 135,137,139,445 --script smb-os-discovery -oA zerologon_nmap -iL <IPList>
 ```

*   Parsing the nmap resoults with the next script and command  <br>   
```
./convert-nmap-zerologon.py zerologon_nmap | grep "yes" | awk -F "|" '{print $1"," $4}' > ZeroLogonScan.txt

```