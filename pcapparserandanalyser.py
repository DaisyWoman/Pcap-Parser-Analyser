import requests
import re, json, random, os, argparse , base64
from scapy.all import TCP, rdpcap, packet
from scapy.layers import http
from io import IOBase, BytesIO

gonul = """  
             ____   ____    _    ____    ____                             ___        _                _                        _____           _ 
            |  _ \ / ___|  / \  |  _ \  |  _ \ __ _ _ __ ___  ___ _ __   ( _ )      / \   _ __   __ _| | _   _ ___  ___ _ __  |_   _|__   ___ | |
            | |_) | |     / _ \ | |_) | | |_) / _` | '__/ __|/ _ \ '__|  / _ \/\   / _ \ | '_ \ / _` | || | | / __|/ _ \ '__|   | |/ _ \ / _ \| |
            |  __/| |___ / ___ \|  __/  |  __/ (_| | |  \__ \  __/ |    | (_>  <  / ___ \| | | | (_| | || |_| \__ \  __/ |      | | (_) | (_) | |
            |_|    \____/_/   \_\_|     |_|   \__,_|_|  |___/\___|_|     \___/\/ /_/   \_\_| |_|\__,_|_| \__, |___/\___|_|      |_|\___/ \___/|_|
                                                                                                         |___/                                    
                                                                                                                         Development: Gönül POLAT     
                                                                                                                                  
"""

VT_API_KEY = "f01114f93052b4534fce7308988ff069df6b1ef9bb2383723bb38872aa0d56dc"
VT_DOMAİN_URL = "https://www.virustotal.com/vtapi/v2/domain/report"
VT_FILESCAN_URL = "https://www.virustotal.com/vtapi/v2/file/scan"
VT_FILEREPORT_URL = "https://www.virustotal.com/vtapi/v2/file/report"
 
def read_pcap_file(file):
    print(f"Packages in a pcap file: {packets}")
    sessions = packets.sessions()
    return packets, sessions

def dump_to_json(parsed_dict, part_name):
    output_file = pcap_file.split("/")
    output_file = output_file[-1]
    output_file = output_file + "_" + part_name + ".json"

    with open(output_file, "w") as f:
        json.dump(parsed_dict, f, indent=2)

    return parsed_dict

def create_host_dir(dr, rand_num):
    if os.path.exists(dr):
        dr = f"{dr}_{rand_num}"
        os.mkdir(dr)
    else:
        os.mkdir(dr)
    return dr

def parse_http_request(sessions):
    data = {}
    host_counter = 0
    for session, pkt in sessions.items():
        for packet in sessions[session]:
            if packet.haslayer(http.HTTPRequest):
                http_layer = packet.getlayer(http.HTTPRequest)
                raw_req = str(http_layer)
                headers = raw_req.split("\\r\\n")
                headers.pop(-1)  # "'" -> (packet[TCP].payload).split("\\r\\n")
                headers.pop(-1)  # ''  -> (packet[TCP].payload).split("\\r\\n")

                # Counter değerinden dönen host için tüm http header ve bodylerini 'data' değişkenine aktarma.
                data[f"Host{host_counter}"] = {}
                data[f"Host{host_counter}"]["Method"] = http_layer.Method.decode()
                data[f"Host{host_counter}"]["Path"] = http_layer.Path.decode()
                data[f"Host{host_counter}"]["HTTP_Version"] = packet[TCP].Http_Version.decode()
                data[f"Host{host_counter}"]["Host"] = http_layer.Host.decode()

                # yukarıda bir kaç header yakaladığımız için dizin 2 den başlat.
                for i in range(2, len(headers)):
                    hdr = headers[i].split(": ")
                    data[f"Host{host_counter}"][hdr[0]] = hdr[1]

                data[f"Host{host_counter}"]["Raw_Request"] = base64.b64encode(bytes(http_layer)).decode()

                host_counter += 1
    return data


def parse_http_response(sessions):
    data = {}
    host_counter = 0
    for session, pkt in sessions.items():
        for packet in sessions[session]:
            response_headers = []

            if packet.haslayer(http.HTTPResponse):
                http_layer = packet.getlayer(http.HTTPResponse)
                headers = str(http_layer).split("\\r\\n\\r\\n")
                hdrs = headers[0]
                post_body = http_layer.payload

                data[f"Host{host_counter}"] = {}
                data[f"Host{host_counter}"]["Http_Version"] = http_layer.Http_Version.decode()
                data[f"Host{host_counter}"]["Status_Code"] = http_layer.Status_Code.decode()
                temp = hdrs.split("\\r\\n")

                for i in range(1, len(temp)):
                    hdr = temp[i].split(": ")
                    data[f"Host{host_counter}"][hdr[0]] = hdr[1]

                data[f"Host{host_counter}"]["POST_Body"] = base64.b64encode(post_body.load).decode()
                data[f"Host{host_counter}"]["Raw Request"] = base64.b64encode(bytes(http_layer)).decode()

                # POST Body'den verileri çıkarıp diske yazma
                if (
                    "Content-Type" or "content-type" or "Content-type" or "content-Type"
                ) in data[f"Host{host_counter}"]:
                    if re.search("[iI]mage\/", str(http_layer)):
                        print(f"[+]Writing image to the disk...")

                        rand_num = random.randrange(1000000, 9999999999999)

                        h = f"Host_{host_counter}"
                        dr = create_host_dir(h, rand_num)
                        filename = f"{dr}/{rand_num}"

                        with open(filename, "wb") as f:
                            f.write(post_body)

                host_counter += 1
    return data

def find(key, jsondata):
    for k, v in jsondata.items():
        if k == key:
            yield v
        elif isinstance(v, dict):
            for result in find(key, v):
                yield result
        elif isinstance(v, list):
            for d in v:
                for result in find(key, d):
                    yield result

#Works request json file 
def vt_hostscan(data):
    if isinstance(data, IOBase):
        data = json.load(data)

    hosts = find("Host", data)
    results = []
    for host in hosts:
        print(f"Host name: {host}")
        params = {"apikey": VT_API_KEY, "domain": host}
        response = requests.get(VT_DOMAİN_URL, params=params)
        response_json = response.json()
        print("[*]Virustotal is scanning...")
        if (
            response_json.get("detected_downloaded_samples")
            or response_json.get("detected_urls")
            or response_json.get("detected_referrer_samples")
        ):
            print("Suspicious!")
        elif(
            response_json.get("undetected_downloaded_samples")
            or response_json.get("undetected_urls")
            or response_json.get("undetected_referrer_samples")
        ):
            print("Nothing suspicious not found!")
            
            
        results.append(response_json)

    with open("hostscan.json", "w") as json_io:
        json.dump(results, json_io, indent=4)

#Works response json file 
def vt_filescan(data):
    if isinstance(data, IOBase):
        data = json.load(data)

    bodies = find("POST_Body", data)
    for _body in bodies:
        post_body = base64.b64decode(_body)
        file_io = BytesIO(post_body)

        #file scan
        filescan_params = {"apikey": VT_API_KEY}
        files = {"file": ("body.txt", file_io)}
        filescan_response = requests.post(VT_FILESCAN_URL, files=files, params=filescan_params)
        filescan_json = filescan_response.json()
        print("[*]Virustotal is scanning...")
        with open("filescan.json", "w") as filescan_json_io:
            json.dump(filescan_json, filescan_json_io, indent=4)

        # file report
        filereport_params = {"apikey": VT_API_KEY, "resource": filescan_json["md5"]}
        filereport_response = requests.get(VT_FILEREPORT_URL, params=filereport_params)
        filereport_json = filereport_response.json()
        print("[*]Virustotal Scanning...")
        if filereport_json.get("positives") > 0:
                print("Suspicious!")
        elif filereport_json.get("positives") == 0:
            print("Nothing suspicious not found!")

        with open("filesrepot.json", "w") as filereport_json_io:
            json.dump(filereport_json, filereport_json_io, indent=4)


if __name__ == "__main__":
    print(gonul)
    pcap_file = ""
    parser = argparse.ArgumentParser( description="pcapparserandanalyser.py - Welcome to PCAP Parser & Analyser Tool")
    parser.add_argument("-p", "--parse", metavar="<pcap file name>", help=" pcap file to pars")
    parser.add_argument("-jp", metavar="<json file name>", help=" json file to pars")
    parser.add_argument("-vthost", help= "virustotal scan of host names", action='store_true')
    parser.add_argument("-vtfile", help= "virustotal scan of file from postbody ", action='store_true')
    args = parser.parse_args()
    pcap_file = args.parse
    jsonfile = args.jp
    vthost_scan=args.vthost
    vtfile_scan=args.vtfile

    if jsonfile:
        with open(jsonfile) as json_io:
            if vthost_scan:
                vt_hostscan(json_io)
            elif vtfile_scan:
                vt_filescan(json_io)      
    elif pcap_file:
        packets = rdpcap(pcap_file)
        print(f"[*]Reading PCAP File: {pcap_file}")
        pkts, sessions = read_pcap_file(pcap_file)

        print(f"[*]Trying to parse HTTP Requests...")
        http_reqs = parse_http_request(sessions)

        print(f"[*]Trying to parse HTTP Responses...")
        http_resp = parse_http_response(sessions)

        print(f"[*]Writing HTTP Requests to JSON file...")
        request_json = dump_to_json(http_reqs, "http_request")
        if vthost_scan:
            vt_hostscan(request_json)

        print(f"[*]Writing HTTP Responses to JSON file...")
        response_json= dump_to_json(http_resp, "http_response")
        if vtfile_scan:
            vt_filescan(response_json)
         
