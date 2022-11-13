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
            # end += 10

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

def get_from_query(query_str,part,ommit,begin=0,end=0):
    part_len = len(part)
    begin_index,end_index = index_of_part(query_str,part,ommit,begin,end)
    return query_str[begin_index+part_len:end_index+part_len],end_index


def locate_section(query_str,begin_symbol,end_symbol,begin = 0,end = 0):
    begin_section,end_section = index_of_part(query_str,begin_symbol,end_symbol,begin,end)
    
    return end_section



def iterative_query(query,cname,count,qtype,qid):
    webAddress = None
    former = query
    timeout = True
    i = 0
    a = None
    # ask root DNS
    
    while(None == a):
        try:
            # a = create_dns_query_and_send(ROOTNAME[i],query_webName,qtype,qid)
            a = query.send(ROOTNAME[i],timeout=3)
        except:
            i += 1
            if i > 3:
                raise("Access root failed")
            continue
    print(count,", ",ROOTNAME[i])
    response = DNSRecord.parse(a)
    response_str = str(response)
    ans = response.header.a
    query_webName = str(response.q.get_qname())
    
    # number of authority DNS server, if there is some, meaning we can go to ask one of them.

    authority = response.header.auth
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
            q = DNSRecord.question(dns_query_webName)
            q.header.id = int(qid)
            next_dns,a,count,cname= iterative_query(q,cname,count,qtype,qid)
            que = DNSRecord.parse(a)
            que.q.qname = str(former.q.qname)
            a = bytes(DNSRecord.pack(que))
            count += 1
            print(count,", ",next_dns)
        while(timeout):
            # sleep(1)
            try:
                # a = create_dns_query_and_send(next_dns,query_webName,qtype,qid)
                a = query.send(next_dns,timeout=3)
                timeout = False
            except:
                next_dns,end_pos = get_from_query(response_str,"IN      A       ","\n",end_pos,end_pos)
                count += 1
                print(count,", ",next_dns)
                # continue
        response = DNSRecord.parse(a)
        response_str = str(response)
        ans = response.header.a
        query_webName = str(response.q.get_qname())
        authority = response.header.auth
        
        
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
        q = DNSRecord.question(query_webName)
        q.header.id = int(qid)
        webAddress,a,count,cname = iterative_query(q,cname,count,qtype,qid)

    
    return webAddress,a,count,cname


def main():
    count = 0       
    serverPort = 1234
    serverName = "127.0.0.1"
    
    # create a cache to store ip address that has been previously found
    Local_DNS_cache = {}
    Local_DNS_record = {}
    
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
            a = Local_DNS_record[query_webName]
            q = DNSRecord.parse(a)
            q.header.id = int(qid)
            q.header.ra = 1
            a = bytes(DNSRecord.pack(q))
            
        
        # cache miss, ask DNS to find it
        else:
            
            # flag = 0, ask public server
            if flag == 0:
                a = query.send(PUBLIC_SERVER)
                query = DNSRecord.parse(a)
                query_str = str(query)
                end_pos = locate_section(query_str,"ANSWER SECTIO",":")
                webAddress,end_pos= get_from_query(query_str,"IN      A       ","\n",end_pos,end_pos)
            
            # flag = 1, do iterative query
            else:
                webAddress , a , count , cname = iterative_query(query,cname,count,qtype,qid)
                # load web ip and cname into cache
                        
            
            # load web ip into cache
            Local_DNS_cache[query_webName] = webAddress 

            
            # create a DNS response and send it to client with answer
            al = DNSRecord.parse(a)
            return_ans = DNSRecord.question(str(query.q.qname))
            cname_list = cname.split(",")
            
            # load web ip and cname into cache
            num_ans = 0
            for item in cname_list:
                if item != "":
                    items = item.split(":")
                    Local_DNS_cache[items[1]] = webAddress
                    return_ans.add_answer(*RR.fromZone(items[0]+ " CNAME "+items[1]))
                    num_ans += 1

            # create response and send to client
            for i in al.rr:
                return_ans.add_answer(*RR.fromZone(str(i)))
                num_ans += 1

            return_ans.header.ra = 1
            return_ans.header.aa = num_ans
            return_ans.header.id = int(qid)

            a = bytes(DNSRecord.pack(return_ans))
            for item in cname_list:
                if item != "":
                    items = item.split(":")
                    Local_DNS_record[items[1]] = a
            Local_DNS_record[query_webName] = a
            
            cname = ""
        
        serverSocket.sendto(a,clientAddress) 
          
        print("The ip address for ",query_webName," is ",webAddress)      

        

if __name__ == "__main__":
    main()
