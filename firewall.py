import csv
import operator

class Ip_info:
    list_startip=[0,0,0,0]
    list_endip = [0,0,0,0]

class port_info:
    def __init__(self,port_start, port_end, ip_info):
        self.port_start = port_start
        self.port_end = port_end
        self.ip_info = ip_info


class firewall:
 rules_map = {}
 all_ports = False
 all_ips  = False

 def __init__(self,firewallpath):
   self.Firewall_path = firewallpath
   with open(self.Firewall_path) as Csvfile:
        read_line = csv.reader(Csvfile,delimiter=',')
        for col in read_line:
            self.adding_rules(col)

 def adding_rules(self,col):
     direction_input = col[0]
     protocol_input = col[1]
     port_input = col[2].split('-')
     ip_input = col[3].split('-')
     if direction_input not in self.rules_map:
        self.rules_map[direction_input] = {}
     if protocol_input not in self.rules_map[direction_input]:
        self.rules_map[direction_input][protocol_input] = {}
        self.rules_map[direction_input][protocol_input]["port_info"]=[]
     node_ip = Ip_info()
     if len(ip_input) > 1:
        start_ip = ip_input[0].split('.')
        end_ip =  ip_input[1].split('.')
        node_ip.list_startip = start_ip
        node_ip.list_endip = end_ip
        if ip_input[0] == '0.0.0.0' and ip_input[1] == '255.255.255.255':
           self.all_ips = True
     else:
        start_ip =  ip_input[0].split('.')
        node_ip.list_startip = start_ip
        node_ip.list_endip = start_ip
     if len(port_input) > 1:
        port_start = port_input[0]
        port_end   = port_input[1]
        if int(port_input[0]) == 0 and int(port_input[1]) == 65535:
           self.all_ports = True
     else:
        port_start = port_input[0]
        port_end = port_input[0]
     self.rules_map[direction_input][protocol_input]["port_info"].append(port_info(port_start,port_end,node_ip))
    # print(self.rules_map)

 def accept_packet(self,direction,protocol,port,ip_address):
     ip_to_check = ip_address.split(".")
     ip_to_check = [int(x) for x in ip_to_check]
     if direction not in self.rules_map or protocol not in self.rules_map[direction]:
         return False
     if self.all_ports and self.all_ips:
         return True
     list_nodes = self.rules_map[direction][protocol]["port_info"]
     return self.check_if_valid_bin_search(list_nodes,port,ip_to_check) # change to check_if_valid for non-binary search method

 def check_if_valid(self,list_nodes,port,ip_to_check):
    #list_nodes.sort(key=operator.attrgetter("port_start","port_end"))
    #print(list_nodes[0].port_start)
    #print(list_nodes[0].port_end)
    for nodes in range(0,len(list_nodes)):
        if port >= int(list_nodes[nodes].port_start) and port <= int(list_nodes[nodes].port_end):
            ip_range_check = list_nodes[nodes].ip_info
            if self.compare_ip(ip_range_check,ip_to_check):
                #print("in compare_ip:")
                return True
    return False

 def check_if_valid_bin_search(self,list_nodes,port,ip_to_check):
     list_nodes.sort(key=operator.attrgetter("port_start","port_end"))
     left = 0
     right = len(list_nodes)-1
     while left <= right:
         mid  = (left + right)//2
         if port >= int(list_nodes[mid].port_start) and port <= int(list_nodes[mid].port_end):
             ip_range_check = list_nodes[mid].ip_info
             if self.compare_ip(ip_range_check,ip_to_check):
                 return True
         elif port > int(list_nodes[mid].port_start) and port > int(list_nodes[mid].port_end):
             left = mid + 1
         else:
             right = mid - 1
     return False

 def port_comparator(self,first, second):
    if first.port_start == second.port_start:
        return first.port_end - second.port_end
    return first.port_start - second.port_start

 def compare_ip(self,ip_range_check,ip_to_check):
    start_ip = ip_range_check.list_startip
    end_ip = ip_range_check.list_endip

    start_greater = True
    for i in range(4): # to check lower Ip range
        if ip_to_check[i] > int(start_ip[i]):
            break
        elif ip_to_check[i] < int(start_ip[i]):
            start_greater = False
            break

    end_lesser = True
    for i in range(4): # to check higher Ip range
        if ip_to_check[i] < int(end_ip[i]):
            break
        elif ip_to_check[i] > int(end_ip[i]):
            end_lesser = False
            break
    return start_greater and end_lesser

def main():
    obj1 = firewall('fw.csv')
    #------------for fw.csv test case-------------------------
    print(obj1.accept_packet("inbound", "tcp", 80, "192.168.1.2"))
    print(obj1.accept_packet("inbound", "udp", 53, "192.168.2.1"))
    print(obj1.accept_packet("outbound", "tcp", 10234, "192.168.10.11"))
    print(obj1.accept_packet("inbound", "tcp", 81, "192.168.1.2"))
    print(obj1.accept_packet("inbound", "udp", 24, "52.12.48.92"))
    #------------for fw1.csv test case------------------------
    #print(obj1.accept_packet("inbound", "tcp", 80, "192.168.1.2"))
    #print(obj1.accept_packet("outbound", "tcp", 80, "192.168.1.2"))
    #------------for fw2.csv test case------------------------
    #print(obj1.accept_packet("inbound", "tcp", 80, "192.168.1.2"))
    #print(obj1.accept_packet("inbound", "udp", 80, "192.168.1.2"))
if __name__=="__main__":main()
