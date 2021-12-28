#!/usr/bin/env python
import os,shutil
import subprocess
import os.path
from subprocess import check_call
from pyfiglet import Figlet
from termcolor import colored
from simple_colors import *
import psycopg2
import datetime;
  

def banner():
     print("""\033[1;32m
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
                          █████████  ████                          █████     █████████                                                             
                          ███░░░░░███░░███                         ░░███     ███░░░░░███                                                            
                         ███     ░░░  ░███   ██████  █████ ████  ███████    ░███    ░░░   ██████   ██████   ████████   ████████    ██████  ████████ 
                        ░███          ░███  ███░░███░░███ ░███  ███░░███    ░░█████████  ███░░███ ░░░░░███ ░░███░░███ ░░███░░███  ███░░███░░███░░███
                        ░███          ░███ ░███ ░███ ░███ ░███ ░███ ░███     ░░░░░░░░███░███ ░░░   ███████  ░███ ░███  ░███ ░███ ░███████  ░███ ░░░ 
                        ░░███     ███ ░███ ░███ ░███ ░███ ░███ ░███ ░███     ███    ░███░███  ███ ███░░███  ░███ ░███  ░███ ░███ ░███░░░   ░███     
                         ░░█████████  █████░░██████  ░░████████░░████████   ░░█████████ ░░██████ ░░████████ ████ █████ ████ █████░░██████  █████    
                          ░░░░░░░░░  ░░░░░  ░░░░░░    ░░░░░░░░  ░░░░░░░░     ░░░░░░░░░   ░░░░░░   ░░░░░░░░ ░░░░ ░░░░░ ░░░░ ░░░░░  ░░░░░░  ░░░░░     
                                                                                                                                                    Coded By Jagadeesh Ram Ch
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
                                                                  Note: Please give numerical numbers for selection
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
""")
    
def convertToBinaryData(filename):
    # Convert digital data to binary format
    with open(filename, 'rb') as file:
        binaryData = file.read()
    return binaryData

def write_file(data, filename):
    # Convert binary data to proper format and write it on Hard Disk
    with open(filename, 'wb') as file:
        file.write(data)


def retrive(path):
    print("Reading data from  database")
    
    print(path)
    os.system("mkdir db_reports")
    os.chdir("db_reports")
    os.system("mkdir Trivy ")
    os.system("mkdir clair")
    os.system("mkdir grype")
    os.system("mkdir combine")
    os.chdir("..")
    
    print(""" 
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
                                                                                    Tools
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
                                                                                (1) Trivy
                                                                                (2) Clair
                                                                                (3) Grype-Anchore
                                                                                (4) All Tools
                                                                                (5) Back
                                                                                (6) Exit
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
""")
    ID=int(input("Please select your tool to retrive data:"))
    
    try:
        connection = psycopg2.connect(database='scanner', user='scan', password='password', host='127.0.0.1', port= '5432')
        cursor = connection.cursor()
        if ID==1:
            output = subprocess.getoutput('''sudo -u postgres psql scanner -c "select id,file_name,time_stamp  from Trivy"''')
            print("\5t",output)
            fetch_id=int(input("Enter your choice to fetch report:"))
            post_query = """SELECT * from Trivy where Id = %s"""
            cursor.execute(post_query, (fetch_id,))
            record = cursor.fetchall()
            for row in record:
                file = row[3]
                d_path=path+"/db_reports/Trivy/"+row[1]+".txt"
                print(d_path)
                print("Storing employee image and bio-data on disk  {} \n".format(d_path))
                write_file(file,d_path)
                
        if ID==2:
             
             
            output = subprocess.getoutput('''sudo -u postgres psql scanner -c "select id,file_name,time_stamp  from Clair"''')
            print("\5t",output)
            fetch_id=int(input("Enter your choice to fetch report:"))
            post_query = """SELECT * from Clair where Id = %s"""
            cursor.execute(post_query, (fetch_id,))
            record = cursor.fetchall()
            for row in record:
                file = row[3]
                d_path=path+"/db_reports/clair/"+row[1]+".txt"
                print(d_path)
                print("Storing employee image and bio-data on disk  {} \n".format(d_path))
                write_file(file,d_path)
                
        if ID==3:
            output = subprocess.getoutput('''sudo -u postgres psql scanner -c "select id,file_name,time_stamp  from Grype"''')
            print("\5t",output)
            fetch_id=int(input("Enter your choice to fetch report:"))
            post_query = """SELECT * from Grype where Id = %s"""
            cursor.execute(post_query, (fetch_id,))
            record = cursor.fetchall()
            for row in record:
                file = row[3]
                d_path=path+"/db_reports/grype/"+row[1]+".txt"
                print(d_path)
                print("Storing employee image and bio-data on disk  {} \n".format(d_path))
                write_file(file,d_path)
                
        if ID==4:
            output = subprocess.getoutput('''sudo -u postgres psql scanner -c "select id,file_name,time_stamp  from Combine"''')
            print("\5t",output)
            fetch_id=int(input("Enter your choice to fetch report:"))
            post_query = """SELECT * from Combine where Id = %s"""
            cursor.execute(post_query, (fetch_id,))
            record = cursor.fetchall()
            for row in record:
                file = row[3]
                d_path=path+"/db_reports/combine/"+row[1]+".txt"
                print(d_path)
                print("Storing employee image and bio-data on disk  {} \n".format(d_path))
                write_file(file,d_path)

        if ID==5:
             dem()
        if ID==6:
            exit()

    except (Exception, psycopg2.DatabaseError) as error:
        print("Failed inserting  data into Postgres table {}".format(error))
    
    
    


    

def creation():
   
    os.system("sudo -u postgres createdb scanner")
    os.system("sudo -u postgres createuser scan")
    
    order='''sudo -u postgres psql -c "alter user scan with password 'password'"'''
    os.system(order)  
    order1='''sudo -u postgres psql -c "grant all privileges on database scanner to scan"'''
    os.system(order1)
    connection = psycopg2.connect(database='scanner', user='scan', password='password', host='127.0.0.1', port= '5432')
    print("connetion successful")
    #connection = psycopg2.connect(database='scanner', user='scan', password='password', host='127.0.0.1', port= '5432')
    connection.autocommit = True
    cursor = connection.cursor()
    cursor.execute("DROP TABLE IF EXISTS Trivy")
    cursor.execute("DROP TABLE IF EXISTS Clair")
    cursor.execute("DROP TABLE IF EXISTS Grype")
    cursor.execute("DROP TABLE IF EXISTS Combine")
    sql ='''CREATE TABLE Trivy(ID  SERIAL PRIMARY KEY,file_name text, Time_stamp text,file bytea)'''
    cursor.execute(sql)
    sql1 ='''CREATE TABLE Clair(ID  SERIAL PRIMARY KEY,file_name text, Time_stamp text,file bytea)'''
    cursor.execute(sql1)
    sql2 ='''CREATE TABLE Grype(ID  SERIAL PRIMARY KEY,file_name text, Time_stamp text,file bytea)'''
    cursor.execute(sql2)
    sql3='''CREATE TABLE Combine(ID  SERIAL PRIMARY KEY,file_name text, Time_stamp text,file bytea)'''
    cursor.execute(sql3)
    print("Table created successfully........")   
    
def connection():
    os.system("sudo systemctl start postgresql")
    Check=str(input(red("Are you creating database for first time (y|n):","bold")))
    if Check=='y' or Check=='Y':
        creation()
    else:
        C=str(input(blue( 'DO you delete previous one and create new one again (y|n):','bold')))
        #output = subprocess.getoutput('''sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='scanner'"''')
        #if output=="1":
        if C=='y' or C=='Y':
              os.system("sudo -u postgres dropdb scanner")
              os.system("sudo -u postgres dropuser scan")
              creation()
        else:
            pass


def dem():
    print("""
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
									Choose Your Option
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
									(1) Install Tools
									(2) Scanning
									(3) Data Base Reports
									(4) Exit
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
""")


def ubuntu():
    os.system("sudo apt update")
    os.system("sudo apt -y upgrade")
    os.system("sudo apt-get install -y libpq-dev")
    os.system(" sudo apt install -y postgresql postgresql-client")
    
    os.system("clear")
    connection()
    banner()
    print(""" 
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
                                                                                    Tools
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
                                                                                (1) Trivy
                                                                                (2) Clair
                                                                                (3) Grype-Anchore
                                                                                (4) All Tools
                                                                                (5) Exit
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
""")
    c=int(input("Please Select to tool to install:"))
    if c==1:
        cmd = os.system("sudo apt-get install wget apt-transport-https gnupg lsb-release && wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key |sudo apt-key add -  && echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | sudo tee -a /etc/apt/sources.list.d/trivy.list && sudo apt-get -y update && sudo apt-get install -y trivy")
        os.system("clear")
       
    elif c==2:
        path=os.getcwd()
        os.system("sudo snap install --classic --channel=1.17/stable go")
        os.system("export PATH=$PATH:/usr/local/go/bin")
        print( " We need \"go 1.16\" for this tool ")
        output = subprocess. getoutput("lsb_release -r | grep Release| awk '{print $2}'")
        os.system("sudo apt-get install curl wget gnupg2 -y")
        order1='echo "deb https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/xUbuntu_{}/ /" | sudo tee  /etc/apt/sources.list.d/devel:kubic:libcontainers:stable.list'.format(output)
        os.system(order1)
        order2='curl -L "https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/xUbuntu_{}/Release.key" | sudo apt-key add -'.format(output)
        os.system(order2)
        os.system("sudo apt-get update")
        os.system("sudo apt-get -y upgrade")
        os.system("sudo apt-get -y install podman")
            #cmd =os.system("sudo apt install golang-go")
        p=path.split("/")
        p_path=("/"+p[1]+"/"+p[2])
        os.chdir(p_path)
        cmd =os.system("sudo git clone https://github.com/quay/clair.git")
        cmd=os.system("cd | GO111MODULE=on go get github.com/quay/clair/v4/cmd/clairctl@latest ")
        os.chdir(path)
        os.system("clear")
        
    elif c==3:
        cmd=os.system("sudo curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin ")
        os.chdir(path)
        os.system("clear")
        
    elif c==4:
        cmd = os.system("sudo apt-get install wget apt-transport-https gnupg lsb-release && wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -  && echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | sudo tee -a /etc/apt/sources.list.d/trivy.list && sudo apt-get update && sudo apt-get install trivy")
        cmd=os.system("sudo curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin ")
        path=os.getcwd()
        os.system("sudo snap install --classic --channel=1.17/stable go")
        os.system("export PATH=$PATH:/usr/local/go/bin")
        print( " We need \"go 1.16\" for this tool ")
        output = subprocess. getoutput("lsb_release -r | grep Release| awk '{print $2}'")
        os.system("sudo apt-get install curl wget gnupg2 -y")
        order1='echo "deb https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/xUbuntu_{}/ /" | sudo tee  /etc/apt/sources.list.d/devel:kubic:libcontainers:stable.list'.format(output)
        os.system(order1)
        order2='curl -L "https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/xUbuntu_{}/Release.key" | sudo apt-key add -'.format(output)
        os.system(order2)
        os.system("sudo apt-get update")
        os.system("sudo apt-get -y upgrade")
        os.system("sudo apt-get -y install podman")
        p=path.split("/")
        p_path=("/"+p[1]+"/"+p[2])
        os.chdir(p_path)
        cmd =os.system("sudo git clone https://github.com/quay/clair.git")
        cmd=os.system("cd | GO111MODULE=on go get github.com/quay/clair/v4/cmd/clairctl@latest ")
        os.chdir(path)
        os.system("clear")
        
        

    elif c==5:
        exit()
        
def debian():
    os.system("sudo apt update")
    os.system("sudo apt -y upgrade")
    #os.system("sudo apt-get install -y libpq-dev")
    os.system(" sudo apt install -y postgresql postgresql-client")
    connection()
    #os.system("clear")
    
    print(""" 
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
                                                                                    Tools
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
                                                                                (1) Trivy
                                                                                (2) Clair
                                                                                (3) Grype-Anchore
                                                                                (4) All Tools
                                                                                (5) Back
                                                                                (6) Exit
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
""")
    d=int(input(red("Please Select tool to install:",'bold')))
    if d==1:
        cmd = os.system("wget https://github.com/aquasecurity/trivy/releases/download/v0.19.2/trivy_0.19.2_Linux-64bit.deb && sudo dpkg -i trivy_0.19.2_Linux-64bit.deb")
        os.system("clear")
    elif d==2:
        path=os.getcwd()
        os.system("sudo apt install golang-go")
        
        os.system("sudo apt-get install -y podman")
        p=path.split("/")
        p_path=("/"+p[1]+"/"+p[2])
        os.chdir(p_path)
        cmd =os.system("sudo git clone https://github.com/quay/clair.git ")
        cmd=os.system("cd | GO111MODULE=on go get github.com/quay/clair/v4/cmd/clairctl@latest ")
        os.chdir(path)
        os.system("clear")
    elif d==3:
        cmd=os.system("sudo curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin ")
        os.system("clear")
    elif d==4:
        cmd = os.system("wget https://github.com/aquasecurity/trivy/releases/download/v0.19.2/trivy_0.19.2_Linux-64bit.deb && sudo dpkg -i trivy_0.19.2_Linux-64bit.deb")
        cmd=os.system("sudo curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin ")
        path=os.getcwd()
        os.system("sudo apt install golang-go")
        os.system("sudo apt-get install -y podman")
        p=path.split("/")
        p_path=("/"+p[1]+"/"+p[2])
        os.chdir(p_path)
        cmd =os.system("sudo git clone https://github.com/quay/clair.git ")
        cmd=os.system("cd | GO111MODULE=on go get github.com/quay/clair/v4/cmd/clairctl@latest ")
        os.chdir(path)
        os.system("clear")
    elif d==5:
        dem()
    elif d==6:
        exit()
                    
def trivy(path):
    file_path=path+"/trivy_reports/"
    if os.path.isfile(file_path):
        pass
    else:
         os.system("mkdir trivy_reports")
    iname=str(input(red("Enter image name:","bold")))
    fname=str(input(yellow("Enter output file name:","bold")))
    file_path=path+"/trivy"+fname+".txt"
    if os.path.isfile(file_path):
        print("File_name exists")
        fname=str(input("Enter output file name:"))
    else:    
        pass
    order="trivy image {} > {}".format(iname,file_path)
    os.system(order)
    
    print("Inserting data to Trivy table")
    try:
        connection = psycopg2.connect(database='scanner', user='scan', password='password', host='127.0.0.1', port= '5432')

        cursor = connection.cursor()
        time= datetime.datetime.now()
        sql_insert_blob_query = """ INSERT INTO Trivy ( file_name, Time_stamp,file) VALUES (%s,%s,%s)"""

        #empPicture = convertToBinaryData(photo)
        file = convertToBinaryData(file_path)
        # Convert data into tuple format
        insert_blob_tuple = (fname, time, file)
        result = cursor.execute(sql_insert_blob_query, insert_blob_tuple)
        connection.commit()
        print("Data and file inserted successfully in Trivy table", result)

    except (Exception, psycopg2.DatabaseError) as error:
        print("Failed inserting data to trivy table {}".format(error))

def clair(path):
    p=path.split('/')
    p_path=p[1]+"/"+p[2]+"/"
    
    file_path=path+"/clair_reports"
    if os.path.isfile(file_path):
        pass
    else:
        os.system("mkdir clair_reports")
        
    a=os.getcwd()
    #print("hh",a)
    os.chdir(path)
    b=os.chdir("..")
    #print(b)
    bb=os.getcwd()
    #print("kk",bb)
    os.chdir("clair")
    a=os.getcwd()
    #print("aa:",a)
    cmd=os.system(" sudo make local-dev-up-with-quay")
    print ("\n")
    print ("""
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
									  Select Format of tool 
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
										(1) GUI                              
										(2) Command Line
										(3) Back
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------""")
    b=int(input(red("Select Format:",'bold')))
    if b==1:
        iname=str(input(red("Enter image name:","bold")))
        tname=str(input(yellow("Enter output file name:","bold")))
        rname=str(input("Enter resp name:"))
        order="podman pull {}".format(iname)
        order1="podman login --tls-verify=false localhost:8080 "
        order2="podman tag {} localhost:8080/{}/{}".format(iname,tname,rname)
        order3="podman push --tls-verify=false localhost:8080/{}/{}".format(tname,rname)
        os.system(order)
        os.system(order1)
        os.system(order2)
        os.system(order3)
    
    if b==2:
        c=os.getcwd()
        cpath=c+"/local-dev/clair/config.yaml"
        #print("bb:",c)
        os.chdir("..") 
        hpath="/"+p_path+"go/bin"
        #print(hpath)
        os.chdir(hpath)
        gpath=os.getcwd()
        #print(gpath)
        
        iname=str(input(red("Enter image name:","bold")))
        fname=str(input(yellow("Enter output file name:","bold")))
        file_path=path+"/clair_reports/"+fname+".txt"
        if os.path.isfile(file_path):
            print("File_name exists")
            fname=str(input("Enter output file name:"))
        else:    
            pass
        order1=" ./clairctl -D  -c {} report {} > {}".format(cpath,iname,file_path)
        cmd=os.system(order1)
        #source1=gpath+"/"+fname
        #scmd=shutil.move(source1,path)
        os.chdir(path)
        try:
            
            connection = psycopg2.connect(database='scanner', user='scan', password='password', host='127.0.0.1', port= '5432')

            cursor = connection.cursor()
            time= datetime.datetime.now()
            sql_insert_blob_query = """ INSERT INTO Clair( file_name, Time_stamp,file) VALUES (%s,%s,%s)"""
            file = convertToBinaryData(file_path)
            insert_blob_tuple = (fname, time, file)
            result = cursor.execute(sql_insert_blob_query, insert_blob_tuple)
            connection.commit()
            print("Data and file inserted successfully in Clair table", result)

        except (Exception, psycopg2.DatabaseError) as error:
            
            print("Failed inserting data to Clair table {}".format(error))
        
    if b==3:
        dem()
        
def grype(path):
    
    file_path=path+"/grype_reports/"
    if os.path.isfile(file_path):
        pass
    else:
        os.system("mkdir grype_reports")
    iname=str(input(red("Enter image name:","bold")))
    fname=str(input(yellow("Enter output file name:","bold")))
    file_path=path+"/grype_reports/"+fname+".txt"
    if os.path.isfile(file_path):
        print("File_name exists")
        fname=str(input("Enter output file name:"))
    else:    
        pass
    order="grype {}  >{} ".format(iname,file_path)
    cmd=os.system(order)
    try:
        connection = psycopg2.connect(database='scanner', user='scan', password='password', host='127.0.0.1', port= '5432')
        cursor = connection.cursor()
        time= datetime.datetime.now()
        sql_insert_blob_query = """ INSERT INTO Grype( file_name, Time_stamp,file) VALUES (%s,%s,%s)"""
        file = convertToBinaryData(file_path)
        insert_blob_tuple = (fname, time, file)
        result = cursor.execute(sql_insert_blob_query, insert_blob_tuple)
        connection.commit()
        print("Data and file inserted successfully in grype table", result)

    except (Exception, psycopg2.DatabaseError) as error:
        print("Failed inserting data to grype table {}".format(error))


def combine(path):
    source=os.getcwd()
    #print(source)
    if os.path.isfile('combine_reports'): 
        os.system("sudo rm -r combine_reports")
    else:
        pass
    cmd=os.system("mkdir combine_reports")
    file_path=path+"/combine_reports/trivy.txt"
    file_path1=path+"/combine_reports/clair.txt"
    file_path2=path+"/combine_reports/grype.txt"
    file_path3=path+"/combine_reports/g.txt"
    dest=os.getcwd()
    time= datetime.datetime.now()
    iname=str(input(orange("Enter image name:","bold")))
    order="trivy image {} > {}".format(iname,file_path)
    cmd=os.system(order)
    order2="grype {}  >{}".format(iname,file_path2)
    cmd=os.system(order2)
    os.chdir(source)
    order3=" grype {} -o template -t  csv.tmpl >{}".format(iname,file_path3)
    cmd=os.system(order3)
    #cmd=shutil.move(source+"/g.txt",dest)
        
    os.chdir("..")
    a=os.getcwd()
    os.chdir("clair")
    c=os.getcwd()
    cpath=c+"/local-dev/clair/config.yaml"
    cmd=os.system(" sudo make local-dev-up-with-quay")
    hpath=os.chdir("..")
    cmd=os.chdir("go/bin")
    order1=" ./clairctl -D -c {} report {} > {}".format(cpath,iname,file_path1)
    cmd=os.system(order1)
    #bpath=os.getcwd()
    #source1=bpath+"/clair.txt"
    #cmd=shutil.move(source1,dest)
    os.chdir(a)
    os.chdir("clair")
    cmd=os.system(" sudo make local-dev-down")
    os.chdir(dest)
    d_path=path+"/combine_reports/"
    os.chdir(d_path)
    cmd=os.system("awk '/CVE/{print $3,$4;}' trivy.txt | sed 's/|/ /g' |sed 's/ //g' > cvet.txt")
    cmd=os.system("awk '/CVE/{print $1}' g.txt | sed 's/ //g'>>cvet.txt")
    cmd=os.system("awk '/CVE/{print $5;}' clair.txt | sed 's/ //g' >> cvet.txt")
    cmd=os.system("sed 's/ //g' cvet.txt >cvett.txt")
    cmd=os.system("sort cvett.txt | uniq >final.txt")
    cmd=os.system("sudo rm g.txt cvet.txt cvett.txt")
    try:
        file_path4=path+"/combine_reports/final.txt"
        connection = psycopg2.connect(database='scanner', user='scan', password='password', host='127.0.0.1', port= '5432')

        cursor = connection.cursor()
        time= datetime.datetime.now()
        post_query = """ INSERT INTO Trivy( file_name, Time_stamp,file) VALUES (%s,%s,%s)"""
        file = convertToBinaryData(file_path)
        insert_blob_tuple = ("trivy", time, file)
        result = cursor.execute(post_query, insert_blob_tuple)
        
        post_query1 = """ INSERT INTO Clair( file_name, Time_stamp,file) VALUES (%s,%s,%s)"""
        file1 = convertToBinaryData(file_path1)
        insert_blob_tuple1 = ("clair", time, file1)
        result = cursor.execute(post_query1, insert_blob_tuple1)
        
        post_query2 = """ INSERT INTO Grype( file_name, Time_stamp,file) VALUES (%s,%s,%s)"""
        file2= convertToBinaryData(file_path2)
        insert_blob_tuple2 = ("grype", time, file2)
        result = cursor.execute(post_query2, insert_blob_tuple2)
        connection.commit()

        post_query3 = """ INSERT INTO Combine( file_name, Time_stamp,file) VALUES (%s,%s,%s)"""
        file3= convertToBinaryData(file_path4)
        insert_blob_tuple3 = ("combine_report", time, file3)
        result = cursor.execute(post_query3, insert_blob_tuple3)
        connection.commit()
        print("Data and file inserted successfully in grype table", result)

    except (Exception, psycopg2.DatabaseError) as error:
        print("Failed inserting data to grype table {}".format(error))
    os.chdir(path)
    
    


while True:
   
    banner()
    print("\n ")
    dem()
    path=os.getcwd()
    a=int(input(blue("Select your option : ","bold")))
    if a==1:
        
        print ("\n")
        print ("""
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
									  Select Your Machine
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
										(1) Ubuntu                                
										(2) Debian
										(3) Database reports
										(4) Exit
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------""")
        b=int(input(red("Select Machine:","bold")))
        if  b==1:
            ubuntu()
        if  b==2:
            debian()
        
        if  b==3:
            exit()
    if a==2:
        os.chdir(path)
        os.system(" sudo systemctl start docker")
        #print(path)
        print(""" 
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
                                                                                    Tools
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
                                                                                (1) Trivy
                                                                                (2) Clair
                                                                                (3) Grype-Anchore
                                                                                (4) Combined Tools
                                                                                (5) Database Reports
                                                                                (6) Back to first
                                                                                (7) Exit
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
                                        Note:  The reports are stored in text file with tool name as file_name,but for combined tools it was stored in reports folder
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
""")
        e=int(input(red("Select Tool to scan:","bold")))
        if e==1:
            trivy(path)
        if e==2:
            clair(path)
        if e==3:
            grype(path)
        if e==4:
            combine(path)
        if e==5:
            retrive(path)
        if e==6:
            dem()
        if e==7:
            exit()
    if  a==3:
         retrive(path)
        
    if a==4:
        exit()

