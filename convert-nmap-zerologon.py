#!/usr/bin/env python3 
#
#
# you might want to
# pip3 install --upgrade simplejson
# pip3 install --upgrade python-libnmap
#

import json
import sys


from libnmap.parser import NmapParser
from libnmap.reportjson import ReportDecoder, ReportEncoder


nmap_out = sys.argv[1]


nmap_report_obj = NmapParser.parse_fromfile(nmap_out)

nmap_report_json = json.dumps(nmap_report_obj, cls=ReportEncoder)
nmap_report_obj = json.loads(nmap_report_json)


hd = {}


  
vuln = 0

for host in nmap_report_obj["__NmapReport__"]["_hosts"]:
  #~ print(host) 
  hd_addr = host["__NmapHost__"]["_ipv4_addr"] 
  ip = hd_addr
  state = { "domain": "", "server_name": "", "fqdn": "", "check": "no" }
  if "hostscript" in host["__NmapHost__"]["_extras"]:
    for scripts in host["__NmapHost__"]["_extras"]["hostscript"]:
      #~ print(scripts)
      if "output" in scripts and scripts["output"].find("Forest") > -1:
        vuln += 1
        server_name = scripts["elements"]["server"]
        if not server_name:
          server_name =  scripts["elements"]["fqdn"].split(".")[0]
        server_name = server_name.split("\\")[0]
        state = { "domain": scripts["elements"]["domain_dns"] , "server_name": server_name, "fqdn": scripts["elements"]["fqdn"], "check": "yes"  }
        print(ip)
      #~ print(hd_addr)
  #~ try:
    #~ state = host["__NMapHost__"["services"]["__NmapService__"]["_service_extras"]["elements"]["NMAP-2"]["state"]
  #~ except:
    #~ pass 
  if state["check"] == "yes" or hd_addr not in hd:
    hd[hd_addr] = {}
    hd[hd_addr]["state"] = state
    hd[hd_addr]["ip"] = ip
    hd[hd_addr]["raw"] = host
    

print(vuln)

for addr in hd:
  print("""%-18s | %3s | %15s | %20s | %s """ % (addr, hd[addr]["state"]["check"], hd[addr]["state"]["domain"], hd[addr]["state"]["server_name"], hd[addr]["state"]["fqdn"]  ))


#~ print(json.dumps(hd))

  

#
# naive approach
#
#~ import json
#~ import xmltodict
#~ import sys
#~ f = open(nmap_out)
#~ xml_content = f.read()
#~ f.close()
#~ print(json.dumps(xmltodict.parse(xml_content), indent=4, sort_keys=True))
