#!/usr/bin/env python
from flask import Flask, jsonify, request
import nmap
import pprint
import json
import re
import subprocess
import sys
import shlex
#from flask_cors import CORS

import time
app = Flask(__name__)
#CORS(app)

import netifaces as ni
ni.ifaddresses('eth0')

try:
    ip = ni.ifaddresses('eth0')[ni.AF_INET][0]['addr']
except:
    ip = "192.168.1.1" 


_code = 0
_result = 0
@app.route('/')
def index():
    return "Hello Index"


@app.route('/services/ycbmaster/stop_services', methods=['GET'])
def stop_services(): 
    action = None
    opcion = request.args.get("opcion")
    if opcion == "1":
        action = "tor"
    if opcion == "2":
        action = "squid"
    if opcion == "3":
        action = "dnstunnel"
    if opcion == "4":
        action = "resolv.conf"
    if opcion == "5":
        action = "all"
    print action

    command_line = "/bin/bash /home/pi/ycbmaster/ycbmaster.sh -z "+str(action)
    args = shlex.split(command_line)
    p = subprocess.Popen(args, stdout=subprocess.PIPE)
    out, err = p.communicate()
    return jsonify(
        {
        'response'  : "200",
        'result'   : "OK"
        }
    )

@app.route('/services/ycbmaster/testdnstunneling', methods=['GET'])
def ycbmaster_testdnstunneling():    

    command_line = "/bin/bash /home/pi/ycbmaster/ycbmaster.sh -o"
    ptn_tunnelingIPLocal = r'.*(OK).*Local:\s(.*)'
    ptn_tunnelingIPExternal = r'.*(OK).*External:\s(.*)'
    args = shlex.split(command_line)
    p = subprocess.Popen(args, stdout=subprocess.PIPE)
    out, err = p.communicate()
    
    status = None
    ipLocal = None
    ipExternal = None
    
    _out = []
    for line in out.splitlines():
        print(line)
        matchObj = re.match(ptn_tunnelingIPLocal, line, re.M|re.I)
        if matchObj:
            ipLocal = matchObj.group(2)
        
        matchObj = re.match(ptn_tunnelingIPExternal, line, re.M|re.I)
        if matchObj:
            status = matchObj.group(1)
            ipExternal = matchObj.group(2)
       
    if None not in (status, ipExternal, ipLocal):
        _out_ = {
            "status"    : status,
            "ipExternal" : ipExternal,
            "ipLocal"        : ipLocal
        }
        _out.append(_out_)
    return jsonify(
        {
        'response'  : "200",
        'result'   : _out
        }
    )

@app.route('/services/ycbmaster/checkevade', methods=['GET'])
def ycbmaster_checkevade():    
    command_line = "/bin/bash /home/pi/ycbmaster/ycbmaster.sh -e"
    ptn_OK = r'.*(OK).*'
    args = shlex.split(command_line)
    p = subprocess.Popen(args, stdout=subprocess.PIPE)
    out, err = p.communicate()
    response = 'error'
    for line in out.splitlines():
        print line
        matchObj = re.match(ptn_OK, line, re.M|re.I)
        if matchObj:
            response = 'ok'
        
    return jsonify(
        {
        'response'  : "200",
        'result'   : response
        }
    )

@app.route('/services/ycbmaster/discovery_vulns', methods=['GET'])
def discovery_vulns():    
    ipv4 = request.args.get("ipv4")
    command_line = "sudo /usr/bin/nmap -sV --script=/usr/share/nmap/scripts/vulscan/vulscan.nse "+ ipv4
    regex_nmap_cve = r'\S\s\SCVE\-(\d+)\-(\d+)\S\s(.*)'
    ptn_serv = r'(\d+)\S(\w+)\s+(\w+)\s+(.*?)\s(.*)'
    args = shlex.split(command_line)
    p = subprocess.Popen(args, stdout=subprocess.PIPE)
    out, err = p.communicate()
    _outDiscovery = []
    _outCVE = []
    port = None
    for line in out.splitlines():
        line2 = line
        matchObj = re.match(ptn_serv, line, re.M|re.I)
        if matchObj:
            port = matchObj.group(1).strip()
            protocol = matchObj.group(2).strip()
            state = matchObj.group(3).strip()
            service = matchObj.group(4).strip()
            version = matchObj.group(5).strip()
            obj = {
                "port"    : port,
                "protocol" : protocol,
                "state"    : state,
                "service" : service,
                "version"    : version
            }
            _outDiscovery.append(obj)
        else:
            matchObj2 = re.match(regex_nmap_cve, line2, re.M|re.I)
            if matchObj2:
                if int(matchObj2.group(1)) > 2016 :
                    cve = "CVE-"+str(matchObj2.group(1))+"-"+str(matchObj2.group(2))
                    desc = matchObj2.group(3).strip()
                    #print cve + " - " + desc
                    obj = {
                        "port"  : port,
                        "cve"    : cve,
                        "desc" : desc[0:50]
                    }
                    _outCVE.append(obj)
    #print _outCVE
    return jsonify(
        {
        'response'  : "200",
        'services'  : _outDiscovery,
        'CVE'       : _outCVE
        }
    )  

@app.route('/services/ycbmaster/dnsresolver', methods=['GET'])
def ycbmaster_dnsresolver():    
    ipv4 = request.args.get("ipv4")
    command_line = "/bin/bash /home/pi/ycbmaster/ycbmaster.sh -s "+ ipv4
    ptn_address = r'.*(OK).*address\s(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})'
        
    args = shlex.split(command_line)
    p = subprocess.Popen(args, stdout=subprocess.PIPE)
    out, err = p.communicate()
    
    status = "error"
    address = "0.0.0.0"
    _out = []
    
    for line in out.splitlines():
        print(line)
        matchObj = re.match(ptn_address, line, re.M|re.I)
        if matchObj:
            status = matchObj.group(1)
            address = matchObj.group(2)
        
    _out_ = {
        "status"    : status,
        "address" : address
    }
    _out.append(_out_)

    return jsonify(
        {
        'response'  : "200",
        'result'   : _out
        }
    )  

@app.route('/services/ycbmaster/dnstunneling', methods=['GET'])
def ycbmaster_dnstunneling():    
    command_line = "/bin/bash /home/pi/ycbmaster/ycbmaster.sh -i"
    ptn_OK = r'.*(OK).*'
    args = shlex.split(command_line)
    p = subprocess.Popen(args, stdout=subprocess.PIPE)
    out, err = p.communicate()
    response = 'error'
    for line in out.splitlines():
        print line
        matchObj = re.match(ptn_OK, line, re.M|re.I)
        if matchObj:
            response = 'ok'
        
    return jsonify(
        {
        'response'  : "200",
        'result'   : response
        }
    )

@app.route('/services/ycbmaster/lan', methods=['GET'])
def ycbmaster_lan():    
    ptn_lan_int = r'.*(OK)\S\slink\s(\w+).*'
    ptn_ip = r'.*(OK)\S\sIP Addr.*\s(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})'
    ptn_gw = r'.*(OK)\S\sGateway.*\s(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})'
        
    command_line = "/bin/bash /home/pi/ycbmaster/ycbmaster.sh -l"
    args = shlex.split(command_line)
    p = subprocess.Popen(args, stdout=subprocess.PIPE)
    out, err = p.communicate()
    
    status = None
    interface = None
    ip = None
    gateway = None
    _out = []
    for line in out.splitlines():
        print(line)
        matchObj = re.match(ptn_lan_int, line, re.M|re.I)
        if matchObj:
            status = matchObj.group(1)
            interface = matchObj.group(2)
        matchObj = re.match(ptn_ip, line, re.M|re.I)
        if matchObj:
            ip = matchObj.group(2)
        matchObj = re.match(ptn_gw, line, re.M|re.I)
        if matchObj:
            gateway = matchObj.group(2)
    if None not in (status, interface, ip, gateway):
        _out_ = {
            "status"    : status,
            "interface" : interface,
            "ip"        : ip,
            "gateway"   : gateway
        }
        _out.append(_out_)
    return jsonify(
        {
        'response'  : "200",
        'result'   : _out
        }
    )

@app.route('/services/ycbmaster/dns', methods=['GET'])
def ycbmaster_dns():    
    ptn_address = r'.*(OK).*address\s(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})'
        
    command_line = "/bin/bash /home/pi/ycbmaster/ycbmaster.sh -d"
    args = shlex.split(command_line)
    p = subprocess.Popen(args, stdout=subprocess.PIPE)
    out, err = p.communicate()
    
    status = "error"
    address = "0.0.0.0"
    _out = []
    
    for line in out.splitlines():
        print(line)
        matchObj = re.match(ptn_address, line, re.M|re.I)
        if matchObj:
            status = matchObj.group(1)
            address = matchObj.group(2)
        
    _out_ = {
        "status"    : status,
        "address" : address
    }
    _out.append(_out_)

    return jsonify(
        {
        'response'  : "200",
        'result'   : _out
        }
    )  


@app.route('/services/ycbmaster/http_tunneling', methods=['GET'])
def ycbmaster_http_tunneling():    
    ptn_status_code = r'.*(OK)\S\sstatus\scode\sis\s(\d+)'
        
    command_line = "/bin/bash /home/pi/ycbmaster/ycbmaster.sh -p"
    args = shlex.split(command_line)
    p = subprocess.Popen(args, stdout=subprocess.PIPE)
    out, err = p.communicate()
    
    status = None
    code = None
    _out = []

    for line in out.splitlines():
        print(line)
        matchObj = re.match(ptn_status_code, line, re.M|re.I)
        if matchObj:
            status = matchObj.group(1)
            code = matchObj.group(2)
        
        
    if None not in (status, code):
        _out_ = {
            "status"    : status,
            "code" : code
        }
        _out.append(_out_)
    return jsonify(
        {
        'response'  : "200",
        'result'   : _out
        }

    )

@app.route('/services/ycbmaster/http', methods=['GET'])
def ycbmaster_http():    
    ptn_status_code = r'.*(OK)\S\sstatus\scode\sis\s(\d+)'
        
    command_line = "/bin/bash /home/pi/ycbmaster/ycbmaster.sh -w"
    args = shlex.split(command_line)
    p = subprocess.Popen(args, stdout=subprocess.PIPE)
    out, err = p.communicate()
    
    status = "error"
    code = "200"
    _out = []

    for line in out.splitlines():
        print(line)
        matchObj = re.match(ptn_status_code, line, re.M|re.I)
        if matchObj:
            status = matchObj.group(1)
            code = matchObj.group(2)
        
        
        
    if None not in (status, code):
        _out_ = {
            "status"    : status,
            "code" : code
        }
        _out.append(_out_)
    return jsonify(
        {
        'response'  : "200",
        'result'   : _out
        }

    )  

@app.route('/services/ycbmaster/https', methods=['GET'])
def ycbmaster_https():    
    ptn_status_code = r'.*(OK)\S\sstatus\scode\sis\s(\d+)'
        
    command_line = "/bin/bash /home/pi/ycbmaster/ycbmaster.sh -q"
    args = shlex.split(command_line)
    p = subprocess.Popen(args, stdout=subprocess.PIPE)
    out, err = p.communicate()
    
    status = "error"
    code = "200"
    _out = []

    for line in out.splitlines():
        print(line)
        matchObj = re.match(ptn_status_code, line, re.M|re.I)
        if matchObj:
            status = matchObj.group(1)
            code = matchObj.group(2)
  
            _out_ = {
                "status"    : status,
                "code" : code
            }
            _out.append(_out_)
    return jsonify(
        {
        'response'  : "200",
        'result'   : _out
        }
    )

@app.route('/services/ycbmaster/vulns', methods=['GET'])
def ycbmaster_vulns():

    ipv4 = request.args.get("ipv4")
    
    
    ptn_serv = r'(\d+)\S(\w+)\s+(\w+)\s+(.*?)\s(.*)'
    command_line = "sudo nmap -sV "+ipv4
    args = shlex.split(command_line)
    p = subprocess.Popen(args, stdout=subprocess.PIPE)
    out, err = p.communicate()
    _out = []
    status = None
    code = None
    #print "lines"
    for line in out.splitlines():
        #print line
        matchObj = re.match(ptn_serv, line, re.M|re.I)
        if matchObj:
            port = matchObj.group(1).strip()
            protocol = matchObj.group(2).strip()
            state = matchObj.group(3).strip()
            service = matchObj.group(4).strip()
            version = matchObj.group(5).strip()
            obj = {
                "port"    : port,
                "protocol" : protocol,
                "state"    : state,
                "service" : service,
                "version"    : version
            }
            _out.append(obj)

    return jsonify(
                {
                'response'  : 200,
                'msg'   : 'OK',
                'result': _out
                }
            )
@app.route('/services/discovery',methods=['GET'])
def get_discovery():
    ptn_ip = r'Nmap scan report for\s(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})'
    ptn_rest = r'MAC Address:\s(.*?)\s\S(.*)\S'
    command_line = "sudo nmap -sP "+ip+"/24"
    args = shlex.split(command_line)
    p = subprocess.Popen(args, stdout=subprocess.PIPE)
    out, err = p.communicate()
    hosts = []
    status = None
    code = None
    ipv4 = None
    mac = None
    vendor = None
    status =  None
    #print "lines"
    print out
    for line in out.splitlines():
        print line
        matchObj = re.match(ptn_ip, line, re.M|re.I)
        if matchObj:
            ipv4 = matchObj.group(1).strip()
        else:
            matchObj2 = re.match(ptn_rest, line, re.M|re.I)
            if matchObj2:
                mac = matchObj2.group(1).strip()
                vendor = matchObj2.group(2).strip()
                status = "up"

        

                host =  {
                    "ipv4" : ipv4,
                    "mac" : mac,
                    "vendor" : vendor,
                    "status" : status,
                    "types" : ''
                }
                hosts.append(host)
            
   
    return jsonify(
                {
                'response'  : 200,
                'msg'   : 'OK',
                'result': hosts
                }
            )
@app.route('/services/discoverySudo',methods=['GET'])
def get_discoverySudo():
    hosts = []
    nm = nmap.PortScanner() 
    myscan = nm.scan(ip+'/24', arguments='-sP')   

    for k,v in myscan['scan'].iteritems(): 
        ipv4 = ""
        mac = ""
        vendor = ""
        status = "" 
        status = str(v['status']['state'])
        if status == 'up':
            ipv4 = str(v['addresses']['ipv4'])
            try : mac = str(v['addresses']['mac'])
            except: mac = ""
            try :vendor = str(v['vendor'][str(v['addresses']['mac'])])
            except: vendor = ""

            host =  {
                "ipv4" : ipv4,
                "mac" : mac,
                "vendor" : vendor,
                "status" : status,
                "types" : ''
            }
            hosts.append(host)
            
   
    return jsonify(
                {
                'response'  : 200,
                'msg'   : 'OK',
                'result': hosts
                }
            )

@app.route('/services/vulners', methods=['POST'])
def call_vulners():
    req_data = request.get_json()
    targetsTmp = req_data['listip']
    name = req_data['name']
    description = req_data['description']
    targets = ""
    for item in targetsTmp:
        if(targets == ""):
            targets = item
        else:
            targets += "," + item

    print targets

    print id
    report_id = int(time.time())
    conn = mysql.connect()
    cursor = conn.cursor()
    try:
        cursor.execute('''insert into reports values(%s,now(),0,%s,%s);''', (report_id, name, description))
        conn.commit()
    except Exception as e:
        print("Problem inserting into db: " + str(e))

    myList = [description, name, str(report_id), targets]
    
    #import os
    #myList = [description, name, "name3"]
    #pid = subprocess.Popen("/usr/bin/python /home/pi/services/report.py","hello",str("asds"),  shell=True)
    subprocess.Popen(['python' , "/home/pi/services"  + "/report.py"   ] + myList)
    #print "pid: " + str(pid)
    #report = Reports()
    #report_result = report.createTask(ts,targets)
    
    #if(report_result == "ok"):
    _code = 200
    _result = "ok"

    return jsonify(
                {
                'response'  : str(_code),
                'msg'   : str(_result),
                'report_id': report_id
                }
            )


if __name__ == '__main__':   
  app.run(host='0.0.0.0' , port=5000,debug=True,threaded=True)
  
