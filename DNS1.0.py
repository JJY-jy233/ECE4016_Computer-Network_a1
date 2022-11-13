
from socket import *
from dnslib import *
from dnslib.server import *

ROOTNAME = ["202.12.27.33","192.203.230.10","198.41.0.4","192.228.79.201"]
PUBLIC_SERVER = "10.20.232.47"
def index_of_part(str,part,ommit,begin = 0,end = 0):
    begin_flag = True
    end_flag = True
    part_len = len(part)
    str_len = len(str)
    while((begin_flag or end_flag) and end+part_len < str_len):
        if(str[begin:begin+part_len] != part and begin_flag):
            begin += 1
            end += 1
            continue
        else:
            begin_flag = False
     
        if(begin_flag == False and str[end+part_len] != ommit):
            end += 1
        else:
            end_flag = False
    if begin == end:
        raise(error)
    return begin, end

def get_basic_info(query_str):
    begin_id , end_id = index_of_part(query_str,"id: ","\n",0,0)
    begin_ans, end_ans = index_of_part(query_str,"ANSWER: ",",",end_id,end_id)
    begin_web ,end_web =index_of_part(query_str,"N SECTION:\n;"," ",end_ans,end_ans)
    begin_type, end_type = index_of_part(query_str,"IN      ","\n",begin_web,begin_web)
    return query_str[begin_id+4:end_id+4],query_str[begin_ans+8:end_ans+8], query_str[begin_web+12:end_web+12] , query_str[begin_type+8:end_type+8]

def get_additional_number(query_str,begin = 0,end = 0):
    begin_addi,end_addi = index_of_part(query_str,"ADDITIONAL: ","\n",begin,end)
    return query_str[begin_addi+12:end_addi+12]

def get_authority_number(query_str,begin = 0,end = 0):
    begin_addi,end_addi = index_of_part(query_str,"AUTHORITY: ",",",begin,end)
    return query_str[begin_addi+11:end_addi+11]

def get_from_query(query_str,part,ommit,begin=0,end=0):
    part_len = len(part)
    begin_index,end_index = index_of_part(query_str,part,ommit,begin,end)
    return query_str[begin_index+part_len:end_index+part_len],end_index

def create_dns_query_and_send(des,query_webName,qtype,qid):
    query = DNSRecord.question(query_webName,qtype)
    query.header.id = int(qid)
    query.header.ra = 1
    response = query.send(des,timeout=5)
    return response

def locate_section(query_str,begin_symbol,end_symbol,begin = 0,end = 0):
    begin_section,end_section = index_of_part(query_str,begin_symbol,end_symbol,begin,end)
    # begin_ip_after_ans,end_ip_after_ans = index_of_part(query_str,type,"\n",end_section,end_section)
    
    return end_section



def iterative_query(cname,count,query_webName,qtype,qid):
    webAddress = None
    timeout = True
    i = 0
    # ask root DNS
    a = None
    while(None == a):
        try:
            a = create_dns_query_and_send(ROOTNAME[i],query_webName,qtype,qid)
        except:
            i += 1
            if i > 3:
                raise("Access root failed")
            continue
    print(count,", ",ROOTNAME[i])
    response = DNSRecord.parse(a)
    response_str = str(response)
    qid,ans,query_webName,qtype = get_basic_info(response_str)
    
    # number of authority DNS server, if there is some, meaning we can go to ask one of them.
    authority = get_authority_number(response_str)
    while(int(ans) == 0 and int(authority) > 0):
        timeout = True
        try:
            addi_end_pos = locate_section(response_str,"ADDITIONAL SECTIO",":")
            next_dns,end_pos = get_from_query(response_str,"IN      A       ","\n",addi_end_pos,addi_end_pos)
            count += 1
            print(count,", ",next_dns)
        except:
            # find the upper DNS to
            auth_end_pos = locate_section(response_str,"AUTHORITY SECTIO",":")
            dns_query_webName,endd_pos = get_from_query(response_str,"NS      ","\n",auth_end_pos,auth_end_pos)
            count += 1
            # website for dns server
            next_dns,a,count,cname= iterative_query(cname,count,dns_query_webName,qtype,qid)
            count += 1
            print(count,", ",next_dns)
        while(timeout):
            # sleep(1)
            try:
                a = create_dns_query_and_send(next_dns,query_webName,qtype,qid)
                timeout = False
            except:
                next_dns,end_pos = get_from_query(response_str,"IN      A       ","\n",end_pos,end_pos)
                count += 1
                print(count,", ",next_dns)
                # continue
        response = DNSRecord.parse(a)
        response_str = str(response)
        qid,ans,query_webName,qtype = get_basic_info(response_str)
        authority = get_authority_number(response_str)
        
    # try to extract ip address from response, if not, meaning there is cname
    if int(ans) > 0:
        try:
            end_pos= locate_section(response_str,"ANSWER SECTIO",":")
            webAddress,end_pos = get_from_query(response_str,"IN      A       ","\n",end_pos,end_pos)
        except:
            cname += query_webName + ":"
            end_pos = locate_section(response_str,"ANSWER SECTIO",":")
            query_webName,end_pos = get_from_query(response_str,"IN      CNAME   ","\n",end_pos,end_pos)
            cname += query_webName + ","
            print("CNAME: " + query_webName)
            
        
    if None == webAddress:
        count += 1
        webAddress,a,count,cname = iterative_query(cname,count,query_webName,qtype,qid)
        # count += 1
        # print(count,", ",next_dns)

    
    return webAddress,a,count,cname

        
    




def main():
    count = 0       
    serverPort = 1234
    serverName = "127.0.0.1"
    
    # create a cache to store ip address that has been previously found
    Local_DNS_cache = {}
    
    # create socket and bind to port 1234 in our localhost
    serverSocket = socket.socket(AF_INET,SOCK_DGRAM)
    serverSocket.bind((serverName,serverPort))
    
    
    flag = int(input("please enter flag (1 or 0): "))
    
    while(1):
        count = 0
        cname = ""
        
        # get dns query from client
        message,clientAddress = serverSocket.recvfrom(2048)
        
        # get the infomation from query including qid,query_webName,qtype
        query = DNSRecord.parse(message)
        query_str = str(query)  
        qid,ans,query_webName,qtype = get_basic_info(query_str)
        
        # first check cache, if cache hit, load it from cache
        webAddress = Local_DNS_cache.get(query_webName)
        if None != webAddress:
            print("get it from cache:" + webAddress)
        
        # cache miss, ask DNS to find it
        else:
            
            # flag = 0, ask public server
            if flag == 0:
                a = create_dns_query_and_send(PUBLIC_SERVER,query_webName,qtype,qid)
                query = DNSRecord.parse(a)
                query_str = str(query)
                end_pos = locate_section(query_str,"ANSWER SECTIO",":")
                webAddress,end_pos= get_from_query(query_str,"IN      A       ","\n",end_pos,end_pos)
            
            # flag = 1, do iterative query
            else:
                webAddress , a , count , cname = iterative_query(cname,count,query_webName,qtype,qid)
                cname_list = cname.split(",")
                # load web ip and cname into cache
                for item in cname_list:
                    if item != "":
                        Local_DNS_cache[item.split(":")[1]] = webAddress
                cname = ""
                        
            
            # load web ip into cache
            Local_DNS_cache[query_webName] = webAddress 
            # print(Local_DNS_cache)

            
        # create a DNS response and send it to client with answer
        q = DNSRecord.question(query_webName)
        q.header.id = int(qid)
        a = q.replyZone(query_webName+" 60 A "+webAddress)
        a.header.ra = 1
        a = bytes(a.pack()) 
        serverSocket.sendto(a,clientAddress) 
          
        print("The ip address for ",query_webName," is ",webAddress)      

        

if __name__ == "__main__":
    main()
