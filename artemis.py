#!/usr/bin/python

# This is the driving program for the artemis. This program will accept all the required inputs and invoke
# 1. Crawler Module
# 2. Fuzzer Module
# 3. Analyzer Module

#import cralwer
import fuzzer
import analyzer
import datetime
import getopt
import sys

# Set up import path
#sys.path.append("./crawler")
sys.path.append("./fuzzer")
sys.path.append("./analyzer")

import fuzzer
import analyzer

# Start of Usage function
def usage():
    print " Artemis "
    print " Options"
    print " Add the explanation for the option details"
# End of Usage function

def start_artemis(argv):
#

#    -b	--base-url		URL of the site to be tested	https://files.stage.acrobat.com
#    -ma	--max-api		Number of APIs to be fuzzed at a single time
#    -mc	--max-conn		Number of connection per API
#    -t	--type	all , custom	Attack type
#    If all , executes all attacks from fuzzdb.
#    If custom execute only specific attacks fom fuzzdb	-t all
#    -t xss
#    -wm	--website-map		Name of the file that contains the Website Map. This will be produced by the Crawler module
#    -o	--output-dir		Output Directory path. This is where the attack request and response will be stored.
#    -n	--name		Unique Name for this testing.
#    -l	--login		File containing Login/Cookie details


#Validate the command line arguments
    try :
        options, remainder = getopt.getopt(argv, 'b:a:c:t:m:o:n:l' , ['base-url=' ,
                                                                      'max-api=' ,
                                                                      'max-conn=' ,
                                                                      'type=' ,
                                                                      'website-map=' ,
                                                                      'output-dir=' ,
                                                                      'name=' ,
                                                                      'login=' ] )
    except getopt.GetoptError , err :
        print str(err)
        usage()
        sys.exit(2)

    if len(argv) == 0 :
        usage()
        sys.exit(2)

    print "No of arguments provided :" , len(argv)
    print "Options" , options
    print "Remainder" , remainder
    for opt , arg in options:
        if opt in ( '-h' , '--help'):
            usage()
            sys.exit(2)
        if  opt in ( '-b' , '--base-url' ):
            base_url = arg
        elif  opt in ( '-a' , '--max-api' ):
            max_api = arg
        elif  opt in ( '-c' , '--max-conn' ):
            max_conn = arg
        elif  opt in ( '-t' , '--type' ):
            attack_type = arg
        elif  opt in ( '-m' , '--website-map' ):
            website_map = arg
        elif  opt in ( '-o' , '--output-dir' ):
            output_dir = arg
        elif  opt in ( '-n' , '--name' ):
            run_name = arg
        elif  opt in ( '-l' , '--login' ):
            login_filename = arg
        else:
            usage()
            sys.exit(2)

    # Print the list of command line options provided.
    print "Base URL : " , base_url
    print "Max  API :"  , max_api
    print "Max Conn :"  , max_conn
    print "Attack Type " , attack_type
    print "Website Map:" , website_map
    print "Output Directory :" , output_dir
    print "Run Name :" , run_name
    print "Login Filename :" , login_filename
    print "Exiting....."
    #sys.exit(2)

    # Initiate Crawler
    # Add code to initiate the crawler and pass the website_map as the output filename , and base_url as the starting point

    # Create the log file
    #log_filename = './log/Artemis-Attack-Log-' + datetime.datetime.now().strftime("%Y-%m-%d-T%H-%M-%S")  # Time
    log_filename = output_dir + '/' + run_name + '-' + datetime.datetime.now().strftime("%Y-%m-%d-T%H-%M-%S")  # Time
    print "Log Filename " , log_filename

    #Initiate Fuzzer
    api_details = 'Dummy'
    fuzzer_object = fuzzer.fuzz(api_details, max_api , max_conn , attack_type , website_map , output_dir , login_filename , log_filename)
    fuzzer_object.prepare_attack()


    #Initiate Analyzer
    NewResponse=analyzer.Response_Analyzer(log_filename)
    NewResponse.Read_Response()

    return "End of the start Artemis function"


if __name__ == "__main__":
    print "\n======================= Welcome to Artemis ===================================="
    print "\n arguments received " , sys.argv
    start_artemis(sys.argv[1:])
    sys.exit(2)
    print "\n=========================== Done =============================================="