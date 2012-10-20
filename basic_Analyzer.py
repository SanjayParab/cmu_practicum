#!/usr/bin/python

import urllib
import json
import random
import re
import httplib2

http_handle=httplib2.Http() 

class Response_Analyzer:
    error500=0
    XSS=0
    FileError=0
    cmd=0
    Vuln=0


    def __init__(self, file_path):
        self.file_path = file_path

    # print "In init"

    def XSS_Analyze(self, url, payload,response):
        global Vuln
        if response.find(payload)>=0:
            #print "XSS (QUERY_STRING) in",page
            #print "\tEvil url:",url
            self.XSS=+1
            self.Vuln+=1
            print"XSS (QUERY_STRING) in Evil url: ", url
            #self.window.findings.append("XSS (QUERY_STRING) in "+page+" Evil url: "+url)
    def FileHandlingAttack_Analyze(self, url ,response):
        global Vuln
        global FileError
        warn=0
        err=""
        if response.find("root:x:0:0")>=0:
            err="Unix include/fread"
            self.FileError+=1
            self.Vuln+=1
        if response.find("[boot loader]")>=0:
            err="Windows include/fread"
            self.FileError+=1
            self.Vuln+=1
        if response.find("<title>Google</title>")>0:
            err="Remote include"
            self.FileError+=1
            self.Vuln+=1
        if response.find("java.io.FileNotFoundException:")>=0 and warn==0:
            err="Warning Java include/open"
            self.FileError+=1
            warn=1
            self.Vuln+=1
        if response.find("fread(): supplied argument is not")>0 and warn==0:
            err="Warning fread"
            self.FileError+=1
            warn=1
            self.Vuln+=1
        if response.find("for inclusion (include_path=")>0 and warn==0:
            err="Warning include"
            self.FileError+=1
            warn=1
            self.Vuln+=1
        if response.find("Failed opening required")>=0 and warn==0:
            err="Warning require"
            self.FileError+=1
            warn=1
            self.Vuln+=1
        if response.find("<b>Warning</b>:  file(")>=0 and warn==0:
            err="Warning file()"
            self.FileError+=1
            warn=1
            self.Vuln+=1
        if response.find("<b>Warning</b>:  file_get_contents(")>=0:
            err="Warning file_get_contents()"
            self.FileError+=1
            warn=1
            self.Vuln+=1
        if err!="":
            #print err,"(QUERY_STRING) in",page
            #print "\tEvil url:",url
            print"Inappropraite File Handling Vulnerability wirh error:", err, "in Evil url: ",url
                #wx.CallAfter(self.window.write_to_box_vuln,"Vulnerable URL: "+url)
                #self.window.findings.append(err+" (QUERY_STRING) in "+page)
                #self.window.findings.append("Vulnerable URL: "+url)
            
            
    def CodeInject_Analyze(self, url ,response):
        global cmd
        global Vuln
        warn=0
        err=""
        if response.find("eval()'d code</b> on line <b>")>=0 and warn==0:
            err="Warning eval()"
            warn=1
            self.Vuln+=1
            self.cmd+=1
        if response.find("PATH=")>=0 or response.find("PWD=")>=0 and warn==0:
            err="Command execution"
            warn=1
            self.Vuln+=1
            self.cmd+=1
        if response.find("Cannot execute a blank command in")>=0 and warn==0:
            err="Warning exec"
            warn=1
            self.Vuln+=1
            self.cmd+=1
        if response.find("Fatal error</b>:  preg_replace")>=0 and warn==0:
            err="preg_replace injection"
            warn=1
            self.Vuln+=1
            self.cmd+=1
        if err!="":
            #print err,"(QUERY_STRING) in",page
            #print "\tEvil url:",url
            #wx.CallAfter(self.window.write_to_box_vuln,err+" (QUERY_STRING) in "+page)
            #wx.CallAfter(self.window.write_to_box_vuln,"Vulnerable URL: "+url)
            #self.window.findings.append(err+" (QUERY_STRING) in "+page)
            #self.window.findings.append("Vulnerable URL: "+url)
            print"Command Injection Vulnerability wirh error:", self.err, "in Evil url: ",url
            


    def Read_Response(self):

        #print "In Read Response File folder"
        apiOn=0
        attackOn=0
        totalattacks=0
        global Vuln
        global error500
        # reading the response and extracted the different pramters of the request &response
        #f = open('Artemis-log.rtf','r')
        f = open(self.file_path,'r')
        #for line in f:
        #line=f.readline()
        while 1:
            line = f.readline()
            if not line:
                    break
            #print "inside loop!!"
            if "API-Start" in line:
                # identifying the attacked API
                totalattacks=0
                self.Vuln=0
                self.error500=0
                self.FileError=0
                self.cmd=0
                apiOn=1
                api=line[11:]
                print "\nAnalyzing Fuzzing Attacks on API: ", api
                line=f.readline()
                #print "nxt line to read",line
            while apiOn==1:
                #print"api loop"
                if "Attack-Start" in line:
                    totalattacks+=1
                    attackOn=1
                    attack_type=line[13:]
                    print "Analyzing response on ", attack_type ,"Attack"
                
                while attackOn==1:
                    line=f.readline()
                        # identifying the attacked URL
                    if "Attack URL" in line:
                        url=line[13:]
                    #print "url ", url
                    # identifying the attack Payload
                    if "Attack Payload " in line:
                        payload=line[17:]
                    # print "payload ", payload
                    if "Attack Type" in line:
                        attack_type=line[13:]
                        print "attack Type ", attack_type
                    # identifying the attacked URL
                    if "Attack Response " in line:
                        response_header=line[20:]
                    #print "header ", response_header
                    # identifying the attacked URL
                    if "Response Content " in line:
                        response=line[20:]
                    #print "response ", response
                    if "Attack-End" in line:
                        attackOn=0
                        
                        # analyzing the status code
                        #if "'status': '500'" in response_header:
                        if "'status': '500'" in response_header:
                            self.error500=+1
                            self.Vuln+=1
                            print "500 HTTP Error code was found with Vulnerable URL: ", url
                        
                        #Response Analysis against vulnerabilties signature(s) : XSS, File Hnadling , Code Injection
                        # analyzing against XSS vulnearbility
                        if "XSS" in attack_type :
                            print "XSS attack sent to be analyzed..."
                            self.XSS_Analyze(url,payload,response)
                        # analyzing against Inappropraite File Handling
                        if "FileHandling" in attack_type:
                            print "File Handling attack sent to be analyzed..."
                            self.FileHandlingAttack_Analyze(url, response)
                        # analyzing against Code Injection Attack
                        if "CodeInjection" in attack_type:
                            print "Code Injection attack sent to be analyzed..."
                            self.CodeInject_Analyze(url ,response)
                        print "End Analyzing response on ", attack_type , "Attack"

                line=f.readline()  
                #print "nxt line to read",line
                if "API-End" in line:
                    line=f.readline()
                    apiOn=0
                    print "Response Analysis Completed on API: ", api,"with total attacks: ",totalattacks ,"The follwoing are the overall results:"
                    print "Total identified Vulnerabilties: ", self.Vuln 
                    print "Total 500 HTTP Error(s):", self.error500
                    # list of all identified vulns

        f.close()
    

if __name__ == "__main__":
   print "A basic web fuzzer anlyzer started ...."
   NewResponse=Response_Analyzer('Artemis-Attack-Log.txt')
   NewResponse.Read_Response()
   #Read_Response()
   print " Response Analysis Completed .."   


