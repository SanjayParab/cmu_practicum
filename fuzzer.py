#!/usr/bin/python

import time
import os
import json
import re
import httplib2
import urllib
import fileinput
import datetime
import sys

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
    api_attack_dictionary = dict()
    fuzz_field_dictionary = dict() # Dictionary which contains which fields to fuzz for the given API
    payload_filename = ''
    comment_symbol = '#'
    max_conn = ''
    TAG_WORD = '<FUZZ>'

    #Constants
    literal_POST = 'POST'
    literal_GET = 'GET'
    literal_DELETE = 'DELETE'
    literal_PUT = 'PUT'

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
        self.website_map_field_delimiter = ';'
        self.comment_symbol = '#'
        #self.max_conn = 5
        #self.api_attack_dictionary

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

        # Open the file and read the line which does not start with the #.
        # Add details to the dictionary
#        self.api_dtls_dict =  {
#            'API_BASE_URL' : 'https://files.stage.acrobat.com/api/aax/folders/OoLyjoI1SvunWyIUO6PrWA' ,
#            'API_METHOD' : 'POST' ,
#            'API_TYPE'   : 'REST',
#            'API_FUZZ_METHOD' : 'xss-rsnake.txt',
#            'API_FIELDS' : "name,on_dup_name",
#            'API_HEADERS' : ''
#        }

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

        if method == self.literal_POST or method == self.literal_PUT :
            response , content = http_handle.request( attack_url , method , headers = header , body = json.dumps(body) )
        elif method == self.literal_GET or method == self.literal_DELETE :
            response , content = http_handle.request( attack_url , method , headers = header )
        else :
            message = "\n\n Artemis : Error : " + str(time.time()) + ' : Unrecognized Method ' + method
            return

        response_time = time.time() - start_time
        #message = "\n\n Artemis : " + str(time.time()) + ': \n\t Attack Response :' + str(response) + ' : \n\t Response Content : ' + str(content)
        message = "\n\n <Response> \n Artemis : " + str(time.time()) + ': \n\t Attack Response Time:' + str(response_time)+ ': \n\t Attack Response :' + str(response) + ' : \n\t Response Content : ' + str(content)
        self.log_message(message)
        print "End of launch attack function"

    # This function is responsible for preparing the attack
    # It will call the launch_attack function to send the attack payload and store the response.
    def prepare_attack(self):
        print "In the attack function"
        print "Opening the file"

        website_map_file_handle = open(self.website_map)
        website_api_attack_details  = website_map_file_handle.readlines()

        print "Print the attack payload line "
        print website_api_attack_details
        print  "End of the attack payload line"

        for line in website_api_attack_details :
            print "\n\tLine = " , line

            # Use the line only if the first character is not the comment
            comment_line = re.match('^#', line)
            if comment_line :
                print "Comment Line = " , line
            else :
                print "Non-Comment Line = " , line

                # Split the line and check if the attack-type is ALL
                api_attack_configuration = line.split(self.website_map_field_delimiter)
                self.api_attack_dictionary = {
                                            'API_BASE_URL' : api_attack_configuration[0] ,
                                            'API_TYPE' : api_attack_configuration[1] ,
                                            'API_METHOD'   : api_attack_configuration[2],
                                            'API_FUZZ_METHOD' : api_attack_configuration[3],
                                            'API_FIELDS' : api_attack_configuration[4]
                                            #'API_HEADERS' :
                                                }
                print "Attack Details"
                print self.api_attack_dictionary
                for key , value in self.api_attack_dictionary.items():
                    print "Key " , key , " value " , value
                    is_fuzzable = re.search(self.TAG_WORD , value )
                    if is_fuzzable :
                        self.fuzz_field_dictionary[key] = value

                print "List of Fields to be fuzzed "
                print self.fuzz_field_dictionary

                # Find no of variables to fuzz and it to fuzz_api_details_dictionary.
                # For each field in fuzz_field_dictionary
                # 1. Open the attack file

                # Determine the file to be used from the fuzzdb
                if self.api_attack_dictionary['API_FUZZ_METHOD'] == 'ALL' :
                    print "Received request for fuzzing with ALL option"
                    self.payload_filename = 'ALL'
                else :
                    self.payload_filename = self.api_attack_dictionary['API_FUZZ_METHOD']

                #Extract the payload from the fuzzdb database
                print "Checking for file :" + self.fuzzdb_path + '\\' + self.payload_filename + ':'
                if os.path.isfile(self.fuzzdb_path + '\\' + self.payload_filename):
                    print "Found the attack file "
                    #message = "\n\n Artemis : " + str(time.time()) + ' : ' + 'Launching the ' +  self.api_attack_dictionary['API_FUZZ_METHOD'] + ' attack against ' + self.api_attack_dictionary['API_BASE_URL']
                    message = "\nAPI-Start: < %s >" %(self.api_attack_dictionary['API_BASE_URL'] )
                    self.log_message(message)

                    # Log the Attack-Start
                    message = "\nAttack-Start: < Fuzz-Method: %s > " %(self.api_attack_dictionary['API_FUZZ_METHOD'])
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
                            'x-csrftoken' :'7hQCzQ_pQ_iREtfnZ0x5oAVxMU2hSd8wR_SUhZZAjgB8',
                            'x-api-client-id' : 'api_browser',
                            'X-Requested-With' :'XMLHttpRequest',
                            'Referer' :'https://files.stage.acrobat.com/',
                            'Pragma' : 'no-cache',
                            'Cache-Control' : 'no-cache',
                            'Cookie' : 'Session_ACOM_FILES=True;History_ACOM_FILES=Free;ADC_AppHostUrl=http%3a%2f%2fstage.acrobat.com%2f;csrftoken=7hQCzQ_pQ_iREtfnZ0x5oAVxMU2hSd8wR_SUhZZAjgB8;AuthHash=cdcSyGWn_Z0;Authorization=eyJhbGciOiJSUzI1NiJ9.eyJpZCI6ImQwMWM0NTk4LTEzZDQtNGU5OC04OGFhLWEyNmQxNzI5OTAwOCIsInNjb3BlIjoiQWRvYmVJRCxza3lib3gsb3BlbmlkIiwiYXMiOiJpbXMtbmExLXN0ZzEiLCJjcmVhdGVkX2F0IjoiMTM1MDgwOTA3NTg4NSIsImV4cGlyZXNfaW4iOiIzNjAwMDAwIiwidXNlcl9pZCI6IjE2ODc1N0U4NTAzQkY5NTAwQTQ5MEQzNUBBZG9iZUlEIiwiY2xpZW50X2lkIjoiU2t5Ym94MSIsInR5cGUiOiJhY2Nlc3NfdG9rZW4ifQ.VnPHTI1y0B2EHb2pNmQd-bsVewpTG1l4jb4VoU5M7K0DCyWO-DRyQ9A1mRR03ZMaeWIRuho0B2xJrYRBOjC5QS1ZUZTQm5vKrcn0evq6m1n_jFekNwTTAb2tm1oePSSgqxykjjchZ3c12vEVGA_bH43xkUOyXdG0gDGj_rBST3s15G0OD6REqgemkd_MCXpcH-QsDqil8kYm6SPjiv6ZgiUfSrjb4Q7efS6LtMpOhDmLW6-LLIWouFQgi92zVo913EGKakiuWenOsWIU1kErW9S-3cvtDnT5atWqqRdiQtY4ppKr4PLywO_RAlvVH-2RPbpjOweDdeA-vAIylcWvBw;mbox=check#true#1350809127|session#1350809066131-166601#1350810927'
                        }

                        attack_url = re.sub(self.TAG_WORD , line.strip() , self.api_attack_dictionary['API_BASE_URL'] )
                        print " Fields " + self.api_attack_dictionary['API_FIELDS']
                        all_fields = self.api_attack_dictionary['API_FIELDS'].split(',')

                        attack_payload=dict()
                        for field in all_fields :
                            attack_payload[field] = line

                        print "Attack Payload " , json.dumps(attack_payload)

                        #attack_payload = { self.api_dtls_dict['API_FIELDS'] : line }
                        #message = '\n\n Request \n\t Attack URL: %s \n\t Method : %s \n\t Attack Type : XSS \n\t Attack Header : %s : \n\t Attack Payload : %s ' %(time.time(), attack_url , self.api_attack_dictionary['API_METHOD'],  attack_header ,  attack_payload)
                        message = "\n\n <Request> \n Artemis : %s : Info : \n\t Attack URL: %s \n\t Method : %s \n\t Attack Type : %s  \n\t Attack Header : %s : \n\t Attack Payload : %s " %(time.time(), attack_url , self.api_attack_dictionary['API_METHOD'], self.api_attack_dictionary['API_FUZZ_METHOD'] , attack_header ,  attack_payload)

                        self.log_message(message)

                        #We have to introduce threading for the launch_attack function.
                        time.sleep(int(60/int(self.max_conn)))
                        self.launch_attack(attack_url ,self.api_attack_dictionary['API_METHOD'],attack_header ,attack_payload )

                    # Add the Attack End to log file
                    message = "\nAPI-End"
                    self.log_message(message)
                elif self.payload_filename == 'ALL':
                    print "Iterate through all the file under fuzzdb/all files directory "
                else :
                    message = "\n\n Artemis : " + str(time.time()) + ': Error :' + ' Attack File ' +  self.api_attack_dictionary['API_FUZZ_METHOD'] + 'does not exists.'
                    self.log_message(message)


        sys.exit(2)

        # Read the fuzzdb attack vector file

        # Read the website map file and launch the attack
        # 1 For each line in website_map file , which doses not start with # , read the line
        # 2 Decompose the line to retrieve the parameters
        # 3 Check the Attack Type specified in the website map file

        # Determine the file to be used from the fuzzdb
        if self.api_attack_dictionary['API_FUZZ_METHOD'] == 'ALL' :
            print "Received request for fuzzing with ALL option"
            self.payload_filename = 'ALL'
        else :
            self.payload_filename = self.api_attack_dictionary['API_FUZZ_METHOD']

        # Loop through all the possible combinations to fuzz
        # Populate fuzz_field_dictionary
#        print "\n\Populating fuzz field dictionary"
#        for key , value in self.api_attack_dictionary.items():
#            print "Key " , key , " value --" , value
#            is_fuzzable = re.search(r'<FUZZ>' , value )
#            print is_fuzzable
#            print is_fuzzable.group()
#            if is_fuzzable :
#                print "Adding key " , key , " to the dictionary"
#                self.fuzz_field_dictionary['key'] = value

        print "\n\nList of Fields to be fuzzed "
        print self.fuzz_field_dictionary
        print "\n\n\nEnd of fuzz_field_dictionary"
        sys.exit(2)

        print "End of prepare attack function"



if __name__ == "__main__":
    print "Welcome to Artemis.fuzz module."
    api_details = 'Dummy'
    fuzzer = fuzz(api_details)
    fuzzer.prepare_attack()
    print " Done"