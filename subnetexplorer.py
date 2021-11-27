# @kshunor 2021 November
# source code works properly only, if you install the required dependecies from requirements.txt
import ipaddress
import nmap3
import json
import xmltodict
import xml.etree.ElementTree as et
import pymongo
from datetime import datetime
import time
import re
import sys
import os
import subprocess
import signal
import pprint
from crontab import CronTab
clear = lambda: os.system('clear')
my_cron = CronTab(user='root')
bevitel = ''
filename = str(datetime.now().strftime("%Y_%m_%d-%I%M%S_%p"))
myclient = pymongo.MongoClient("mongodb://localhost:27017/")
mydb = myclient["test"]
class color:
   
   PURPLE = '\033[1;35;48m'
   CYAN = '\033[1;36;48m'
   BOLD = '\033[1;37;48m'
   BLUE = '\033[1;34;48m'
   GREEN = '\033[1;32;48m'
   YELLOW = '\033[1;33;48m'
   RED = '\033[1;31;48m'
   BLACK = '\033[1;30;48m'
   UNDERLINE = '\033[4;37;48m'
   END = '\033[1;37;0m'

def check_is_digit(input_str):
    if input_str.strip().isdigit():
        return int(input_str)
    else:
        return input_str

class IpCim:
    
    def check_ipv4():
        global bevitel
        #IP cim validalas ipaddress fuggvennyel, jad subnet validalas
        #ameddig nem felel meg az IP/subnet cim a formatumnak ujra keri
        while True:
            try:
                bevitel = input(color.YELLOW+"IPv4 cim (pl.: 192.168.1.1): "+color.END)
                if ipaddress.IPv4Address(bevitel):
                    print(color.GREEN+f"Valid IP"+color.END)
            except ValueError as err:
                print(color.RED + f"\nIP validation error: "+color.END , err)
                continue
            else:
                break

    def check_ipv4_subnet():
        global bevitel
        #IP subnet validalas validalas ipaddress fuggvennyel
        #ameddig nem felel meg a subent formatumnak ujra keri
        while True:
            try:
                bevitel = input(color.YELLOW+"IPv4 subnet (pl.: 192.168.1.0/24): "+color.END)
                if ipaddress.ip_network(bevitel):
                    print(color.GREEN+f"Valid\n"+color.END)
                    
            except ValueError as err:
                print(color.RED +f"\n IP validation error: "+color.END, err)
                continue
            else:
                break   

    #port szam validalas
    def check_port():
        global bev_port
        while True:
            try:
               bev_port = int(input(color.YELLOW+"TCP port (1 - 65535): "+color.END))
            except ValueError:
                print(color.RED +"Error: a TCP portszam egy egesz szam kell legyen." +color.END)
                continue
            else:
                break
        while True:
            if 1 <= bev_port <= 65535:
                print(color.GREEN+'TCP ',bev_port, 'lesz viszgalva! \n'+color.END)
                break
            else:
                print(color.RED +'Nem megfelelo portszam!'+color.END)
                IpCim.check_port()
		
    #fomenu, az egyes funkciok innen elerhetoek. ctrl+c is kilep rendesen, a sigint segitsegevel 
    def func_main():
        valasz = True
        while valasz:
                valasz = input(color.CYAN+"""\n
					[1] IP cim SYN ACK scan \n
					[2] TCP port mogotti szerviz verzio detektalas \n
					[3] Operacios rendszer felismeres \n
					[4] IP alhalozat scan \n
                                        [5] IP cim alapjan allPort kollekcio elozmenyek keresese \n 
                                        [6] TCP port alpjan elozmenyek keresese subnet kollekcioban \n
                                        [7] TCP port alpjan elozmenyek keresese ServiceVersion kollekcioban \n
                                        [8] Serulekenyseg vizsgalat CPE lista alapjan \n
                                        [9] Idozitett alhalozat scan \n
                                        [0] EXIT \n"""+color.END)
                if valasz == '1':
                    print(color.YELLOW+"1-es menu: SYN ACK scan, vizsgalt TCP port tartomany: 1-1024"+color.END)
                    IpCim.working_folder()
                    IpCim.check_ipv4()
                    IpCim.func_synack()
                elif valasz == '2':
                    print(color.YELLOW+"2-es menu: Vizgalando Port mogotti szerviz verzio detektalas"+color.END)
                    IpCim.working_folder()
                    IpCim.check_ipv4()
                    IpCim.check_port()
                    IpCim.func_synack_version()
                elif valasz == '3':
                    print(color.YELLOW+"3-as menu: Operacios rendszer felismeres"+color.END)
                    IpCim.working_folder()
                    IpCim.check_ipv4()
                    print(bevitel)
                    IpCim.func_osDetect()
                elif valasz == '4':
                    print(color.YELLOW+"4-es menu: Alhalozat felterkepezes"+color.END)
                    IpCim.working_folder()
                    IpCim.check_ipv4_subnet()
                    print(bevitel)
                    IpCim.func_subnet()
                elif valasz == '5':
                    print(color.YELLOW+"5-os menu: IP cim alapjan allPort kollekcio elozmenyek keresese"+color.END)
                    IpCim.check_ipv4()
                    IpCim.date_search()
                    IpCim.read_mongo_by_ip()
                elif valasz == '6':
                    print(color.YELLOW+"6-os menu: TCP port alpjan elozmenyek keresese subnet kollekcioban"+color.END)
                    IpCim.date_search()
                    IpCim.check_port()
                    mycoll_custom = "subNet"
                    IpCim.read_by_port(mycoll_custom)
                elif valasz == '7':
                    print(color.YELLOW+"6-os menu: TCP port alpjan elozmenyek keresese ServiceVersion kollekcioban"+color.END)
                    IpCim.date_search()
                    IpCim.check_port()
                    mycoll_custom = "ServiceVersion"
                    IpCim.read_by_port(mycoll_custom)    
                elif valasz == '8':
                    print(color.YELLOW+"7-es menu: Serulekenyseg vizsgalat CPE lista alapjan, CVS > 7"+color.END)
                    IpCim.check_ipv4()
                    print(bevitel)
                    IpCim.func_vuln()
                elif valasz == '9':
                    IpCim.sched_beker()

                elif valasz == '0':
                    print("Viszlat!")
                    sys.exit
                    break
                else:
                    print(color.RED+"Kerlek a menubol valassz\n"+color.END)
                    IpCim.func_main()

    #stealth scan, json parser nelkul is jo lesz a kimenet ha dict-be rakom.
    #query_field es query_value parameterek, mennek at a read_mongo_after_run() fuggvenybe..
    @classmethod
    def func_synack(cls):
        lastrun = str(datetime.now().strftime("%Y.%m.%d-%I:%M:%S_%p"))
        scanner = nmap3.Nmap()
        synack_json = scanner.nmap_subnet_scan(bevitel, '-v -sS')
        filename_1 = filename + '_' + bevitel + '_synack'
        path = '/home/z39n6u/result'
        data = {}
        data = synack_json
        to_mongo = {'IP':bevitel, 'futtatva':lastrun}
        to_mongo.update(data)
        IpCim.write_file(path, filename_1, data)
        mydb.allPort.insert_one(to_mongo)
        print(color.YELLOW+"Eredmeny adtbazisba irasa..... Kesz.......\n"+color.END)
        mycoll = "allPort"
        query_filed = 'futtatva'
        query_value = f"{lastrun}"
        IpCim.read_mongo_after_run(mycoll,query_filed,query_value)
	
    #Verzio scan, sV kapcsoloval, dupla verbose, nagyon beszedes. bevitt port alapjan
    #query_field es query_value parameterek, mennek at a read_mongo_after_run() fuggvenybe..
    @classmethod
    def func_synack_version(cls):
        lastrun = str(datetime.now().strftime("%Y.%m.%d-%I:%M:%S_%p"))
        scanner = nmap3.Nmap()
        synack_version_json = scanner.nmap_version_detection(bevitel, '-sV -vv', f'-p{bev_port}')
        filename_2 = filename + '_' + bevitel + '_version'
        path = '/home/z39n6u/result'
        data = {}
        data = synack_version_json
        to_mongo = {'IP':bevitel, 'TestedPort':bev_port, 'futtatva':lastrun}
        to_mongo.update(data)
        IpCim.write_file(path, filename_2, data)
        mydb.ServiceVersion.insert_one(to_mongo)
        print(color.YELLOW+"Eredmeny adtbazisba irasa..... Kesz.......\n"+color.END)
        mycoll = "ServiceVersion"
        query_filed = 'futtatva'
        query_value = f"{lastrun}"
        IpCim.read_mongo_after_run(mycoll,query_filed,query_value)
	
    #Os detect. nmapben -O, vagy -A
    #query_field es query_value parameterek, mennek at a read_mongo_after_run() fuggvenybe..
    @classmethod
    def func_osDetect(cls):
        lastrun = str(datetime.now().strftime("%Y.%m.%d-%I:%M:%S_%p"))
        scanner = nmap3.Nmap()
        osDetect_json = scanner.nmap_os_detection(bevitel)
        filename_3 = filename + '_' + bevitel + '_osDetect'
        path = '/home/z39n6u/result'
        data = {}
        data = osDetect_json
        to_mongo = {'IP':bevitel, 'futtatva':lastrun}
        to_mongo.update(data)
        IpCim.write_file(path, filename_3, data)
        mydb.osResults.insert_one(to_mongo)
        print(color.YELLOW+"Eredmeny adtbazisba irasa..... Kesz.......\n"+color.END)
        mycoll = "osResults"
        query_filed = 'futtatva'
        query_value = f"{lastrun}"
        IpCim.read_mongo_after_run(mycoll,query_filed,query_value)
    
    #ugyanaz mint a func_synack, csak itt subnetet validalok... akar egybe is mehetne a ket fuggvenny
    #query_field es query_value parameterek, mennek at a read_mongo_after_run() fuggvenybe. ha meg akarjuk jeleniteni a kimenetet
    #amugy skip, es csak mongoba megy at az eredmeny
    @classmethod
    def func_subnet(cls):
        lastrun = str(datetime.now().strftime("%Y.%m.%d-%I:%M:%S_%p"))
        scanner = nmap3.Nmap()
        subnet_json = scanner.nmap_subnet_scan(bevitel, '-v -sS')
        filename_4 = filename + '_' + 'subnet'
        path = '/home/z39n6u/result'
        data = {}
        data = subnet_json
        IpCim.write_file(path, filename_4, data)
        to_mongo = {'subnet':bevitel, 'futtatva':lastrun}      
        to_mongo.update(data)
        mydb.subNet.insert_one(to_mongo)
        print(color.YELLOW+"Eredmeny adtbazisba irasa.....\n"+color.END)
        question = True
        while question:
            question = input(color.YELLOW+"ki szeretnéd iratni az eredmenyt..hosszuu lehet a lista!?"+color.END+color.GREEN+ "Y/"+color.END + color.RED+"N \n"+color.END).lower()
            if question == 'y':
                mycoll = "subNet"
                query_filed = 'futtatva'
                query_value = f"{lastrun}"
                IpCim.read_mongo_after_run(mycoll,query_filed,query_value)
                break
            elif question == 'n':
                break
                IpCim.func_main()
            else:
                break
                print(color.GREEN+"Y"+color.END+"/"+color.RED+"N\n"+color.END)

    #vulners.nse scriptes serulekenyseg detect. internet nelkul csak sima nmap -sV
    #neten veti ossze a talalt CPE-ket az ismert CVE katalogusokkal
    #consol kimenet teljesen jo, meg keszul rola xml fajl is, az is feldolgozhato. kesobb irok parsert xml->json
    @classmethod
    def func_vuln(cls):

        filename_5 = filename + '_' + bevitel + '_vuln' + '.xml'
        lastrun = ''
        lastrun = str(datetime.now().strftime("%Y.%m.%d-%I:%M:%S_%p"))
        kulcs = bevitel
        global path
        path = '/home/z39n6u/result/' + filename_5
        subprocess.call(['nmap', '-sV', '--script', 'vulners' , '--script-args', 'mincvss=7.0', kulcs, '-oX', path])
        with open(path) as vuln_xml:
            vuln_dict = xmltodict.parse(vuln_xml.read())
            vuln_xml.close()
            vuln_json = json.dumps(vuln_dict)

    #fajlkiirast csinalja. a scan fuggvenyekben van meghivva...
    def write_file(path, filename, data):
        filePath_name = path + '/' + filename + '.json'
        with open(filePath_name, 'w') as fpath:
            json.dump(data, fpath)
    
    #eredmeny fajl helye a /home-ban ellenorzi, es letrehozza ha nincs ilyen path.
    def working_folder():
        wfolder = '/home/z39n6u/result'
        isExists = os.path.exists(wfolder)
        if not isExists:
            os.makedirs(wfolder)

    #scan vegen ez olvassa vissza az eremenyt lastrun valtozoban levo timestamp alapjanaztan pretty printelem
    def read_mongo_after_run(mycoll,query_filed,query_value):
        mycoll_read = mydb[mycoll]
        actual = list(mycoll_read.find({f'{query_filed}' : query_value}, {'_id': 0, 'stats': 0}))
        for doc in actual:
            pprint.pprint(doc)
            print("------------------------------------------------------\n")
    
    #datum bekeres mongoban a kereseshez datum alapjan
    def date_search():
        global datum_keres
        datum_keres = input(color.YELLOW+"Datum formatum a kereseshez (pl.: 2021.10.01) YYYY.MM.DD :  "+color.END)

    #ip alapjan es datum alapjan kereses mongoban
    # datum regex, szoval eleg patternt figyel nem datum format.
    def read_mongo_by_ip():
        mycoll_allP = "allPort"
        myquery = {"$and":[{"futtatva":{"$regex":f"{datum_keres}"}}, {"IP": f"{bevitel}"}]}
        mycoll_read_allP = mydb[mycoll_allP]
        read_by_ip_date = list(mycoll_read_allP.find(myquery,{'_id': 0, 'stats': 0}))
        for doc in read_by_ip_date:
            pprint.pprint(doc)
            print("------------------------------------------------------\n")
    
    #myquery erzekeny a dict meg list adatstrukturakra. ezen meg csiszolni kell
    def read_by_port(mycoll_custom): 
        myquery = [{"$unwind" :"$addresses"},{"$match":{"addresses.ports.portid":f"{bev_port}"}},
                                            {"$match":{"futtatva":{"$regex":f"{datum_keres}"}}},
                                            {"$project": {"stats":0,"runtime":0}}]
        mycoll_read_custom = mydb[mycoll_custom]
        read_by_port = list(mycoll_read_custom.aggregate(myquery))
        for doc in read_by_port:
            pprint.pprint(doc)
            print("------------------------------------------------------\n")
		
    #idozito. a futtato fiok cronjat manipulalja. 
    def mm():
        global MM
        while True:
            MM_check = input(color.YELLOW+"Perc (0-59) vagy figyelmenkivul hagyas * karakter: "+color.END) 
            MM = check_is_digit(MM_check)
            
            if type(MM) == str and MM == '*':
                MM = None
                print(color.GREEN+"Perc= "+color.END,MM)
                print("\n")
                break
            elif type(MM) == int and 0<= MM <=59:
                print(color.GREEN+"Perc= "+color.END,MM)
                print("\n")
                break
            else:
                print(color.RED+"0-59 kozotti erteket vagy * ha nemszamit a perc! \n"+color.END)
            
    def hh():
        global HH
        while True:
            HH_check = input(color.YELLOW+"Ora (0-23) vagy figyelmenkivul hagyas * karakter: "+color.END)
            HH = check_is_digit(HH_check)
        
            if type(HH) == str and HH == '*':
                HH = None
                print(color.GREEN+"Ora= "+color.END,HH)
                print("\n")
                break
            elif type(HH) == int and 0<= HH <=23:
                print(color.GREEN+"Ora= "+color.END,HH)
                print("\n")
                break
            else:
                print(color.RED+"0-23 kozotti egesz ora vagy * ha nemszamit! \n"+color.END)
            

    def dom():
        global DOM
        while True:
            
            DOM_check = input(color.YELLOW+"Honap napja (1-31) vagy figyelmenkivul hagyas * karakter : "+color.END)
            DOM = check_is_digit(DOM_check)
            
            if type(DOM) == str and DOM == '*':
                DOM = None
                print(color.GREEN+"Honap napja= "+color.END,DOM)
                print("\n")
                break
            elif type(DOM) == int and 1<= DOM <=31:
                print(color.GREEN+"Honap napja= "+color.END,DOM)
                print("\n")
                break
            else:
                print(color.RED+"1-31 kozotti honap napja vagy * ha nemszamit! \n"+color.END)
            
    def mon():
        global MON
        while True:
            
            MON_check = input(color.YELLOW+"Honap (1-12) vagy figyelmenkivul hagyas * karakter : "+color.END)
            MON = check_is_digit(MON_check)
            
            if type(MON) == str and MON == '*':
                MON = None
                print(color.GREEN+"Honap= "+color.END,MON)
                print("\n")
                break
            elif type(MON) == int and 1<= MON <=12:
                print(color.GREEN+"Honap= "+color.END,MON)
                print("\n")
                break
            else:
                print(color.RED+"1-12 kozotti honap vagy * ha nemszamit! \n"+color.END)
        

    def dow():
        global DOW
        while True:
            
            DOW_check = input(color.YELLOW+"Het napja (0-6, Vas. a nulladik) vagy figyelmenkivul hagyas * karakter :"+color.END)
            DOW = check_is_digit(DOW_check)
            
            if type(DOW) == str and DOW == '*':
                DOW = None
                print(color.GREEN+"Het napja= "+color.END,DOW)
                print("\n")
                break
            elif type(DOW) == int and 0<= DOW <=6:
                print(color.GREEN+"Het napja= "+color.END,DOW)
                print("\n")
                break
            else:
                print(color.RED+"0-6 kozotti het napja vagy * ha nemszamit! \n"+color.END)
    
    def sched_beker():
        clear()
        global utem
        utem = True
        while utem:
            utem = input(color.CYAN+"""\n
                                        ----------------------------------
                                        [S] Feladat ütemezese
                                        [L] Utemezett feladatok listazasa
                                        [D] feladat torlese comment alapjan
                                        [X] Fomenu
                                         .... Valassz betujelet  
                   \n"""+color.END).lower()
            if utem == 's':
                IpCim.check_ipv4_subnet()
                job = my_cron.new(command='/usr/bin/python3 /home/z39n6u/NmapFunc/Subnet_sched.py'+f" {bevitel}", comment=f"{bevitel}")
                IpCim.mm()
                IpCim.hh()
                IpCim.dom()
                IpCim.mon()
                IpCim.dow()
                job.setall(MM,HH,DOM,MON,DOW)
                my_cron.write()
                for item in my_cron.find_command('/usr/bin/python3 /home/z39n6u/NmapFunc/Subnet_sched.py'):
                    print(item)          
            elif utem == 'l':
                print("---------------------------------------------------------------------------------------------------------")
                for item in my_cron.find_command('/usr/bin/python3 /home/z39n6u/NmapFunc/Subnet_sched.py'):
                    print(item)
                print("-------------------------------------------------------------------------------------------------------\n")
            elif utem == 'd':
                del_str = input(color.YELLOW+"Ird be torolni kivant feladat alhalozat cimet: "+color.END)
                for job_to_delete in my_cron.find_comment(f'{del_str}'):
                    print(job_to_delete) 
                    my_cron.remove(job_to_delete)
                    my_cron.write()
                    print(color.YELLOW+"\n !!!torolve a listabol"+color.END)
            elif utem == 'x':
                clear()
                break           
                IpCim.func_main()
            else:
                print(color.RED+"Kerlek a megfelelo karaktert ird be"+color.END)
                    
    # ezert crtl+c kliepesi lehetoseghez signalt figyelek, 
    # ha jona SIGINT vagyis ctrl+c akkor siman kilep, es nem dob Keyboardintrrupt errort
    def signal_handler(signal, frame):
        print("\nViszlat!")
        exit(0)
        
signal.signal(signal.SIGINT, IpCim.signal_handler)
IpCim.func_main()
