#!/usr/bin/python

import time
import os
import json
import re
import httplib2
import urllib
import fileinput
import datetime

# Prepare class models
#The Class should accept the following parameters
# filename of the website maps
# No of APIs to fuzzed at  a time
# No of connections per API
# Attack Type
# FuzzDB file names

#class fuzzer:
#
#    def fuzz_GET(self,api,type,parms_list):
#        return "In fuzz GET function"
#
#    def fuzz_POST(self,api,type,parms_list):
#        return "In fuzz GET function"
#
#    def fuzz_PUT(self,api,type,parms_list):
#        return "In fuzz GET function"
#
#    def fuzz_DELETE(self,api,type,parms_list):
#        return "In fuzz GET function"
#
#    def read_website_map:
#        # Return the line from the Website map file
#        # Format :
#        #API
#        #API Method
#        #API Type
#        #API Option
#        #Fuzz-Method
#        print "In read website map"
#        line= "https://files.stage.acrobat.com/api/aax/folders/:GET:REST:id:XSS"
#        return line
#
#    def execute_fuzzer:
#
#
#
#if __name__ != "__main__":
#
#Algorithm
#
#1.Class fuzzer to accept the name of the API to be fuzzed , basically line extracted from the website maps
#2. Initialize the class with the paramter from line
#3. Determine the type of the function based on the API method ( get , post , delete , put )
#4. Determine the type of the attack vector to be prepared based on the attack type specified in the file
#5. Search the attack file based on the name in the fuzzdb
#    6. for each line in attack vectore file and based on the connections per API limit
#       7. Prepare the header
#       8. Prepare the attack body
#       9. Log the attack vector in the file
#      10. Send the request over thread , as long as the thread count is within the limits
#      11. Capture the response and log it to the file.
#
# Various fuzzing methods
# 1. Use values from fuzzdb
# 2. Range test , using from variable length input
# 3. Header testing
# 4. Encoding


class fuzz:

    #log_filename = './log/Artemis-Attack-Log-' + datetime.datetime.now().strftime("%Y-%m-%d-T%H-%M-%S")  # Time
    fuzzdb_path = ''
    api_dtls_dict = dict()
    payload_filename = ''

#fuzzer_object = fuzzer.fuzz(api_details, max_api , max_conn , attack_type , website_map , output_dir , login_filename )

    def __init__(self,api_details,max_api , max_conn , attack_type , website_map , output_dir , login_filename , log_filename):
        self.api_details = api_details
        self.max_api = max_api
        self.max_conn = max_conn
        self.attack_type = attack_type
        self.website_map = website_map
        self.output_dir = output_dir
        self.login_filename = login_filename
        self.log_filename = log_filename

        #Create a dictionary based on the input details
        #self.api_dtls_dict =  dict()
        self.fuzzdb_path = '.\\all files'
        self.username = 'sanjay.parab@gmail.com'
        self.password = '9702056'

        #Parse the input data to create a dictionary as shown below. The dictionary is hard-codeded as of now for testing

        # File to contain following fields separated by ; and internal field delimiter :
        # API_BASE_URL  - Contains the whole url , with the part to be fuzzed replaced by TAG <FUZZ>
        # API_METHOD : Method to be used
        # APT_TYPE : Rest or Non-Rest API
        # API_FUZZ_METHOD : Expected input is either ALL or specific filename from the fuzzdb.
        # API_FIELDS : Expected input is in the form API_FILED_NAME:<predefined value if any>
        # API_HEADERS : This has to be one of the field to be supplied in headers section

        # Add details to the dictionary
        self.api_dtls_dict =  {
            'API_BASE_URL' : 'https://files.stage.acrobat.com/api/aax/folders/OoLyjoI1SvunWyIUO6PrWA' ,
            'API_METHOD' : 'POST' ,
            'API_TYPE'   : 'REST',
            'API_FUZZ_METHOD' : 'xss-rsnake.txt',
            'API_FIELDS' : "name,on_dup_name",
            'API_HEADERS' : ''
        }

    # Generic module to log the fuzzer actions
    def log_message(self,message):
        log_file_handle = open(self.log_filename,'a')
        log_file_handle.write(message)
        log_file_handle.close()

    # Launch_attack function responsible for :
    # 1. Sending the HTTP Data
    # 2. Capturing the response and the status code
    # 3. Capturing the response time.

    def launch_attack( self, attack_url , method , header , body  ):
        print "In launch attack function "
        http_handle = httplib2.Http(disable_ssl_certificate_validation=True)
        http_handle.add_credentials(self.username , self.password)
        start_time = time.time()
        response , content = http_handle.request( attack_url , method , headers = header , body = json.dumps(body) )
        response_time = time.time() - start_time

        message = "\n\n Artemis : " + str(time.time()) + ': \n\t Attack Response :' + str(response) + ' : \n\t Response Content : ' + str(content)
        self.log_message(message)
        print "End of launch attack function"

    # This function is responsible for preparing the attack
    # It will call the launch_attack function to send the attack payload and store the response.
    def prepare_attack(self):
        print "In the attack function"

        # Determine the file to be used from the fuzzdb
        if self.api_dtls_dict['API_FUZZ_METHOD'] == 'ALL' :
            print "Received request for fuzzing with ALL option"
            self.payload_filename = 'ALL'
        else :
            self.payload_filename = self.api_dtls_dict['API_FUZZ_METHOD']

        #Extract the payload from the fuzzdb database
        print "Checking for file :" + self.fuzzdb_path + '\\' + self.payload_filename + ':'
        if os.path.isfile(self.fuzzdb_path + '\\' + self.payload_filename):
            print "Found the attack file "
            message = "\n\n Artemis : " + str(time.time()) + ' : ' + 'Launching the ' +  self.api_dtls_dict['API_FUZZ_METHOD'] + ' attack against ' + self.api_dtls_dict['API_BASE_URL']
            self.log_message(message)

            #Open the fuzz db file and send the attack payload to function responsile for
            for line in fileinput.input([self.fuzzdb_path + '/'+ self.payload_filename] ):
                #attack_header = ' '
                attack_header =  {
                    'Host' :' files.stage.acrobat.com',
                    'User-Agent' : 'Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:15.0) Gecko/20100101 Firefox/15.0.1',
                    'Accept' : 'application/vnd.adobe.skybox+json;version=1',
                    'Accept-Language' : 'en-us,en;q=0.5',
                    'Accept-Encoding' :'gzip, deflate',
                    'Connection' :' keep-alive',
                    'Content-Type' :'application/vnd.adobe.skybox+json;version=1;charset=utf-8',
                    'x-csrftoken' :'pXPw0nreSTGWy4TRFvWf5AZDH9hBxziK9VpYAiRrHBE8',
                    'x-api-client-id' : 'api_browser',
                    'X-Requested-With' :'XMLHttpRequest',
                    'Referer' :'https://files.stage.acrobat.com/',
                    'Pragma' : 'no-cache',
                    'Cache-Control' : 'no-cache',
                    'Cookie' : 'mbox=check#true#1350512541|session#1350512480435-983611#1350514341;Session_ACOM_FILES=True;History_ACOM_FILES=Free;ADC_AppHostUrl=http%3a%2f%2fstage.acrobat.com%2f;csrftoken=pXPw0nreSTGWy4TRFvWf5AZDH9hBxziK9VpYAiRrHBE8;AuthHash=8XGzA0TR9-4;Authorization=eyJhbGciOiJSUzI1NiJ9.eyJpZCI6IjEyMDQ4YjdhLWU5YTctNDBhYS1iMDdmLTE4NWRiZjBhMTEwOCIsInNjb3BlIjoiQWRvYmVJRCxza3lib3gsb3BlbmlkIiwiYXMiOiJpbXMtbmExLXN0ZzEiLCJjcmVhdGVkX2F0IjoiMTM1MDUxMjQ5NDQ2OSIsImV4cGlyZXNfaW4iOiIzNjAwMDAwIiwidXNlcl9pZCI6IjE2ODc1N0U4NTAzQkY5NTAwQTQ5MEQzNUBBZG9iZUlEIiwiY2xpZW50X2lkIjoiU2t5Ym94MSIsInR5cGUiOiJhY2Nlc3NfdG9rZW4ifQ.MVZTdnu5Gj70puXcQ4MS4jrQ-GFivrIqr5f5zarwAxC6FdFETcHS46m7gfmHHHKTavCEPfyW3U985Ow2albUsYB-1SXN7u85gQXGsCp50li4otNv3nPyYEOxqm5lKYh6_wnuAkFbSEJQuydusMjB23eY8EEv9I-tiNbdSPeGl47JSnZIOEV6ULlMHYsKsYNiFtZcvn8GrABJ_lEpMpNy3samAqS2n4av5dXRjJzr9a4be12RedcQ3mCrzcLLp65D9eG45mjcloOza6Wxaeig90KAhJ7QyP07SEbw0OOlkKmDVtREL3dXnYJN8BxImnii0oss_MiBTVYBHSP9QUr2yQ'
                }

                attack_url = re.sub('<fuzz>' , line.strip() , self.api_dtls_dict['API_BASE_URL'] )
                print " Fields " + self.api_dtls_dict['API_FIELDS']
                all_fields = self.api_dtls_dict['API_FIELDS'].split(',')

                attack_payload=dict()
                for field in all_fields :
                    attack_payload[field] = line

                print "Attack Payload " , json.dumps(attack_payload)

                #attack_payload = { self.api_dtls_dict['API_FIELDS'] : line }
                message = "\n\n Artemis : %s : Info : \n\t Attack URL: %s \n\t Method : %s \n\t Attack Type : XSS \n\t Attack Header : %s : \n\t Attack Payload : %s " %(time.time(), attack_url , self.api_dtls_dict['API_METHOD'],  attack_header ,  attack_payload)
                self.log_message(message )

                #We have to introduce threading for the launch_attack function.
                self.launch_attack(attack_url ,self.api_dtls_dict['API_METHOD'],attack_header ,attack_payload )

        elif self.payload_filename == 'ALL':
            print "Iterate through all the file under fuzzdb/all files directory "
        else :
            message = "\n\n Artemis : " + str(time.time()) + ': Error :' + ' Attack File ' +  self.api_dtls_dict['API_FUZZ_METHOD'] + 'does not exists.'
            self.log_message(message)
        print "End of prepare attack function"



if __name__ == "__main__":
    print "Welcome to Artemis.fuzz module."
    api_details = 'Dummy'
    fuzzer = fuzz(api_details)
    fuzzer.prepare_attack()
    print " Done"