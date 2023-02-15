import sys
import json
import math
import socket
from collections import defaultdict

SLICE = 32

TOPOLOGY = "topology.json"
CONTROL_PLANE = "s1-runtime.json"
DATA_PLANE = "bsic.p4"

class Node:
    def __init__(self, d):
        self.data = d
        self.left = None
        self.right = None

def sortedArrayToBST(arr):
    if not arr:
        return None
 
    mid = (len(arr)) // 2
    root = Node(arr[mid])
    root.left = sortedArrayToBST(arr[:mid])
    root.right = sortedArrayToBST(arr[mid+1:])
    return root

def traverse(node, level, index, dict):
    if not node:
        return

    if node.left is None and node.right is None:
        dict[level][index] = (node.data[0], node.data[1], None, None)
        return

    current_len = len(dict[level+1])+1

    if node.left is None:
        dict[level][index] = (node.data[0], node.data[1], None, current_len)
        traverse(node.right, level+1, current_len, dict)
    elif node.right is None:
        dict[level][index] = (node.data[0], node.data[1], current_len, None)
        traverse(node.left, level+1, current_len, dict)
    else:
        dict[level][index] = (node.data[0], node.data[1], current_len, current_len+1)
        traverse(node.left, level+1, current_len, dict)
        traverse(node.right, level+1, current_len+1, dict)

def btod(n):
    return int(n,2)

def btoip(n):
    address = n.ljust(128, "0")
    sections = [address[i:i+16] for i in range(0, len(address), 16)]
    for index in range(0,8):
        sections[index] = hex(btod(sections[index]))[2:].rjust(4, "0")
    ip_addr = ':'.join(sections)
    return ip_addr

def get_left_endpoints(slices, default):
    match_length = 64 - SLICE
    base_range = []
    base_range.append(["0".rjust(match_length, "0"), "1".rjust(match_length, "1"), default])
    slices.sort(key=lambda x:(len(x[0]),x[0]))

    for next_slice in slices:
        if next_slice[0] == "exact":
            continue
        left = next_slice[0].ljust(match_length, "0")
        right = next_slice[0].ljust(match_length, "1")
        next_hop = next_slice[1]
        
        index = 0
        for range in base_range:
            if btod(left) > btod(range[0]) and btod(left) <= btod(range[1]):
                # if the left endpoint is greater than the left range value and less than or equal to the right range value
                # 1. if the right endpoint is less than the right range value, then the new entry gets sandwiched in between two ranges
                # 2. if the right endpoint is equal to the right range value, then the new entry gets inserted after the current range
                if btod(right) < btod(range[1]):
                    base_range.insert(index+1, [left, right, next_hop])
                    base_range.insert(index+2, [bin(btod(right)+1)[2:].zfill(match_length), range[1], range[2]])
                    range[1] = bin(btod(left)-1)[2:].zfill(match_length)
                    break
                if btod(right) == btod(range[1]):
                    base_range.insert(index+1, [left, right, next_hop])
                    range[1] = bin(btod(left)-1)[2:].zfill(match_length)
                    break
            if btod(left) == btod(range[0]) and btod(left) <= btod(range[1]):
                # if the left endpoint is equal to the left range value and less than or equal to the right range value
                # 1. if the right endpoint is less than the right range value, then the new entry gets inserted before the current range
                # 2. if the right endpoint is equal to the right range value, we only need to modify the current next hop
                if btod(right) < btod(range[1]):
                    range[0] = bin(btod(right)+1)[2:].zfill(match_length)
                    base_range.insert(index, [left, right, next_hop])
                    break
                if btod(right) == btod(range[1]):
                    range[2] = next_hop
                    break
            index += 1

    left_endpoints = []
    for range in base_range:
        left_endpoints.append((range[0], range[2]))

    return left_endpoints

def gen_next_hop_table(database):
    dict = {}

    with open(database, "r") as file:
        for line in file:
            line = line.rstrip()
            elements = line.split(",")
            next_hop = elements[2]
            if next_hop in dict:
                continue
            dict[next_hop] = len(dict)+1

    return dict

def gen_lookup_table(database, next_hop_table):
    dict = defaultdict(list)

    with open(database, "r") as file:
        for line in file:
            line = line.rstrip()
            elements = line.split(",")
            prefix = elements[0]
            length = int(elements[1])
            next_hop = elements[2]

            if length > SLICE:
                dict[prefix[0:SLICE]].append((prefix[SLICE:], next_hop_table[next_hop]))
            elif length == SLICE:
                dict[prefix].append(("exact", next_hop_table[next_hop]))
            else:
                dict[prefix].append(("short", next_hop_table[next_hop]))

    lookup_table = {}

    index = 1
    for prefix in dict:
        if len(dict[prefix]) == 1 and dict[prefix][0][0] == "short":
            lookup_table[prefix] = ("next hop", dict[prefix][0][1])
        elif len(dict[prefix]) == 1 and dict[prefix][0][0] == "exact":
            lookup_table[prefix] = ("next hop", dict[prefix][0][1])
        else:
            lookup_table[prefix] = ("index", index)
            index += 1

    return lookup_table, dict

def gen_bsts(lookup_table, parsed_prefixes):
    dict = {}

    largest_set = 0
    for prefix in parsed_prefixes:
        if (2*len(parsed_prefixes[prefix]))+1 > largest_set:
            largest_set = (2*len(parsed_prefixes[prefix]))+1
    max_levels = math.ceil(math.log2(largest_set))

    for index in range(0, max_levels):
        dict[index] = {}

    for prefix in lookup_table:
        if lookup_table[prefix][0] != "index":
            continue
        initial_index = lookup_table[prefix][1]
        prefixes = parsed_prefixes[prefix]

        default = None
        for entry in prefixes:
            if entry[0] == "exact":
                default = entry[1]
        if default is None:
            max_length = 0
            for default_entry in lookup_table:
                if lookup_table[default_entry][0] != "next hop" or len(default_entry) <= max_length:
                    continue
                current_index = 0
                valid_match = True
                while current_index < len(default_entry):
                    if default_entry[current_index] != prefix[current_index]:
                        valid_match = False
                        break
                    current_index += 1
                if valid_match is True:
                    max_length = current_index
                    default = lookup_table[default_entry][1]

        left_endpoints = get_left_endpoints(prefixes, default)
        root = sortedArrayToBST(left_endpoints)
        level = 0
        traverse(root, level, initial_index, dict)

    return dict
        
def gen_topology(next_hop_table):
    dict = {}

    dict["hosts"] = { "h1": { "ip": "2001:1:1::a/64", "mac": "08:00:00:00:01:11", "commands": ["ip -4 addr flush dev eth0",
                                                                                               "ip -6 addr flush dev eth0",
                                                                                               "ip -6 addr add 2001:1:1::a/64 dev eth0",
                                                                                               "ip -6 route add default via 2001:1:1::ff"] } }
    dict["switches"] = { "s1": { "runtime_json": "sim-topo/" + CONTROL_PLANE } }
    dict["links"] = [ ["h1", "s1-p1"] ]

    id = 2
    for next_hop in next_hop_table:
        if id == 10:
            print("ERROR: too many hosts requested")
            exit(1)
        fields = next_hop.split(":")
        remainder = int(fields[7], base=16) % 2
        if remainder == 0:
            fields[7] = hex(int(fields[7], base=16) + 1)[2:]
        else:
            fields[7] = hex(int(fields[7], base=16) - 1)[2:]
        gateway_ip = ':'.join(fields)
        dict["hosts"][f"h{id}"] = { "ip": f"{next_hop}/64", "mac": f"08:00:00:00:0{id}:{id}{id}", "commands": ["ip -4 addr flush dev eth0",
                                                                                                               "ip -6 addr flush dev eth0",
                                                                                                               f"ip -6 addr add {next_hop}/64 dev eth0",
                                                                                                               f"ip -6 route add default via {gateway_ip}"] }
        dict["links"].append([f"s1-p{id}", f"h{id}"])
        id += 1

    with open(TOPOLOGY, "w") as file:
        json.dump(dict, file, indent=4)

def gen_control_plane(next_hop_table, lookup_table, bsts_table):
    dict = {}

    dict["target"] = "bmv2"
    dict["p4info"] = f"build/{DATA_PLANE}.p4info.txt"
    dict["bmv2_json"] = "build/bsic.json"
    dict["table_entries"] = []

    dict["table_entries"].append({ "table": "MyIngress.next_hop_table",
                                            "default_action": True,
                                            "action_name": "MyIngress.drop",
                                            "action_params": { } })

    id = 2
    for next_hop in next_hop_table:
        dict["table_entries"].append({ "table": "MyIngress.next_hop_table",
                                                "match": { "meta.next_hop_index": next_hop_table[next_hop] },
                                                "action_name": "MyIngress.ipv6_forward",
                                                "action_params": { "dstAddr": f"08:00:00:00:0{id}:{id}{id}", "port": id } })
        id += 1

    for prefix in lookup_table:
        if lookup_table[prefix][0] == "next hop":
            action_name = "set_next_hop_index"
            action_data = "nhi"
        else:
            action_name = "set_bst_index"
            action_data = "bi"
        
        dict["table_entries"].append({ "table": "MyIngress.lookup_table",
                                                "match": { f"hdr.ipv6.dstAddr": [ btoip(prefix), len(prefix) ] },
                                                "action_name": f"MyIngress.{action_name}",
                                                "action_params": { f"{action_data}": lookup_table[prefix][1] } })

    for index in range(0, len(bsts_table)):
        for key in bsts_table[index]:
            next_hop = bsts_table[index][key][1]
            left_index = bsts_table[index][key][2]
            right_index = bsts_table[index][key][3]
            if next_hop is None:
                next_hop = 0
            if left_index is None:
                left_index = 0
            if right_index is None:
                right_index = 0
            dict["table_entries"].append({ "table": f"MyIngress.bst_{index}_table",
                                                    "match": { "meta.bst_index": key },
                                                    "action_name": "MyIngress.node_action",
                                                    "action_params": { "prefix": btod(bsts_table[index][key][0]),
                                                                       "next_hop": next_hop,
                                                                       "left_index": left_index,
                                                                       "right_index": right_index } })
    
    with open(CONTROL_PLANE, "w") as file:
        json.dump(dict, file, indent=4)

def main(argv):
    if len(argv) != 1:
        print("ERROR: missing argument")
        exit(1)

    database = argv[0]

    next_hop_table = gen_next_hop_table(database)
    lookup_table, parsed_prefixes = gen_lookup_table(database, next_hop_table)
    bsts_table = gen_bsts(lookup_table, parsed_prefixes)

    gen_topology(next_hop_table)
    gen_control_plane(next_hop_table, lookup_table, bsts_table)

if __name__ == "__main__":
    main(sys.argv[1:])
