import yaml
import json
import urllib.request
import logging
import geoip2.database
import requests
import socket
import re
# 提取节点
def process_urls(url_file, processor):
    try:
        with open(url_file, 'r') as file:
            urls = file.read().splitlines()

        for index, url in enumerate(urls):
            try:
                response = urllib.request.urlopen(url)
                data = response.read().decode('utf-8')
                processor(data, index)
            except Exception as e:
                logging.error(f"Error processing URL {url}: {e}")
    except Exception as e:
        logging.error(f"Error reading file {url_file}: {e}")
#提取clash节点
def process_clash(data, index):
    content = yaml.safe_load(data)
    proxies = content.get('proxies', [])
    for i, proxy in enumerate(proxies):
        location = get_physical_location(proxy['server'])
        proxy['name'] = f"{location} {proxy['type']} {index}{i+1}"
    merged_proxies.extend(proxies)

def get_physical_location(address):
    address = re.sub(':.*', '', address)  # 用正则表达式去除端口部分
    try:
        ip_address = socket.gethostbyname(address)
    except socket.gaierror:
        ip_address = address

    try:
        reader = geoip2.database.Reader('GeoLite2-City.mmdb')  # 这里的路径需要指向你自己的数据库文件
        response = reader.city(ip_address)
        country = response.country.name
        city = response.city.name
        #return f"{country}_{city}"
        return f"{country}"
    except geoip2.errors.AddressNotFoundError as e:
        print(f"Error: {e}")
        return "Unknown"

# 处理sb，待办
def process_sb(data, index):
    try:
        json_data = json.loads(data)
        # 处理 shadowtls 数据

        # 提取所需字段
        method = json_data["outbounds"][0]["method"]
        password = json_data["outbounds"][0]["password"]
        server = json_data["outbounds"][1]["server"]
        server_port = json_data["outbounds"][1]["server_port"]
        server_name = json_data["outbounds"][1]["tls"]["server_name"]
        shadowtls_password = json_data["outbounds"][1]["password"]
        version = json_data["outbounds"][1]["version"]
        location = get_physical_location(server)
        name = f"{location} ss {index}"
        # 创建当前网址的proxy字典
        proxy = {
            "name": name,
            "type": "ss",
            "server": server,
            "port": server_port,
            "cipher": method,
            "password": password,
            "plugin": "shadow-tls",
            "client-fingerprint": "chrome",
            "plugin-opts": {
                "host": server_name,
                "password": shadowtls_password,
                "version": int(version)
            }
        }

        # 将当前proxy字典添加到所有proxies列表中
        merged_proxies.append(proxy)

    except Exception as e:
        logging.error(f"Error processing shadowtls data for index {index}: {e}")

def process_hysteria(data, index):
    try:
        json_data = json.loads(data)
        # 处理 hysteria 数据
        # 提取所需字段
        auth = json_data["auth_str"]
        server_ports = json_data["server"]
        server_ports_slt = server_ports.split(":")
        server = server_ports_slt[0]
        ports = server_ports_slt[1]
        ports_slt = ports.split(",")
        server_port = int(ports_slt[0])
        if len(ports_slt) > 1:
            mport = ports_slt[1]
        else:
            mport = server_port
        #fast_open = json_data["fast_open"]
        fast_open = True
        insecure = json_data["insecure"]
        server_name = json_data["server_name"]
        alpn = json_data["alpn"]
        protocol = json_data["protocol"]
        location = get_physical_location(server)
        name = f"{location} hysteria {index}"

        # 创建当前网址的proxy字典
        proxy = {
            "name": name,
            "type": "hysteria",
            "server": server,
            "port": server_port,
            "ports": mport,
            "auth_str": auth,
            "up": 80,
            "down": 100,
            "fast-open": fast_open,
            "protocol": protocol,
            "sni": server_name,
            "skip-cert-verify": insecure,
            "alpn": [alpn]
        }

        # 将当前proxy字典添加到所有proxies列表中
        merged_proxies.append(proxy)

    except Exception as e:
        logging.error(f"Error processing hysteria data for index {index}: {e}")
# 处理hysteria2
def process_hysteria2(data, index):
    try:
        json_data = json.loads(data)
        # 处理 hysteria2 数据
        # 提取所需字段
        auth = json_data["auth"]
        server_ports = json_data["server"]
        server_ports_slt = server_ports.split(":")
        server = server_ports_slt[0]
        ports = server_ports_slt[1]
        ports_slt = ports.split(",")
        server_port = int(ports_slt[0])
        #fast_open = json_data["fastOpen"]
        fast_open = True
        insecure = json_data["tls"]["insecure"]
        sni = json_data["tls"]["sni"]
        location = get_physical_location(server)
        name = f"{location} hysteria2 {index}"

        # 创建当前网址的proxy字典
        proxy = {
            "name": name,
            "type": "hysteria2",
            "server": server,
            "port": server_port,
            "password": auth,
            "fast-open": fast_open,
            "sni": sni,
            "skip-cert-verify": insecure
        }

        # 将当前proxy字典添加到所有proxies列表中
        merged_proxies.append(proxy)

    except Exception as e:
        logging.error(f"Error processing hysteria2 data for index {index}: {e}")

#处理xray
def process_xray(data, index):
    proxy = None
    try:
        json_data = json.loads(data)
        logging.debug(f"Processing data for index {index}: {json_data}")

        outbounds = json_data.get("outbounds", [])
        if not outbounds:
            logging.warning(f"No 'outbounds' found for index {index}")
            return

        first_outbound = outbounds[0]
        protocol = first_outbound.get("protocol", "")
        logging.debug(f"Protocol found: {protocol}")

        if protocol == "vless":
            settings = first_outbound.get("settings", {})
            vnext = settings.get("vnext", [{}])[0]
            streamSettings = first_outbound.get("streamSettings", {})

            server = vnext.get("address", "")
            port = vnext.get("port", "")
            uuid = vnext.get("users", [{}])[0].get("id", "")
            istls = True
            flow = vnext.get("users", [{}])[0].get("flow", "")
            network = streamSettings.get("network", "")
            realitySettings = streamSettings.get("realitySettings", {})
            publicKey = realitySettings.get("publicKey", "")
            shortId = realitySettings.get("shortId", "")
            serverName = realitySettings.get("serverName", "")
            fingerprint = realitySettings.get("fingerprint", "")
            isudp = True
            location = get_physical_location(server)
            name = f"{location} vless {index}"

            if network == "tcp":
                proxy = {
                    "name": name,
                    "type": protocol,
                    "server": server,
                    "port": port,
                    "uuid": uuid,
                    "network": network,
                    "tls": istls,
                    "udp": isudp,
                    "flow": flow,
                    "client-fingerprint": fingerprint,
                    "servername": serverName,
                    "reality-opts": {
                        "public-key": publicKey,
                        "short-id": shortId
                    }
                }
                logging.debug(f"TCP Proxy: {proxy}")

            elif network == "grpc":
                grpcSettings = streamSettings.get("grpcSettings", {})
                serviceName = grpcSettings.get("serviceName", "")
                proxy = {
                    "name": name,
                    "type": protocol,
                    "server": server,
                    "port": port,
                    "uuid": uuid,
                    "network": network,
                    "tls": istls,
                    "udp": isudp,
                    "flow": flow,
                    "client-fingerprint": fingerprint,
                    "servername": serverName,
                    "grpc-opts": {
                        "grpc-service-name": serviceName
                    },
                    "reality-opts": {
                        "public-key": publicKey,
                        "short-id": shortId
                    }
                }
                logging.debug(f"GRPC Proxy: {proxy}")

        elif protocol == "vmess":
            settings = first_outbound.get("settings", {})
            vnext = settings.get("vnext", [{}])[0]
            streamSettings = first_outbound.get("streamSettings", {})

            server = vnext.get("address", "")
            port = vnext.get("port", "")
            uuid = vnext.get("users", [{}])[0].get("id", "")
            alterId = vnext.get("users", [{}])[0].get("alterId", 0)
            network = streamSettings.get("network", "")
            security = streamSettings.get("security", "none")
            location = get_physical_location(server)
            name = f"{location} vmess {index}"

            if network == "tcp":
                proxy = {
                    "name": name,
                    "type": protocol,
                    "server": server,
                    "port": port,
                    "uuid": uuid,
                    "alterId": alterId,
                    "cipher": "auto",
                    "network": network,
                    "tls": security == "tls",
                    "udp": True
                }
                logging.debug(f"TCP Proxy: {proxy}")

            elif network == "ws":
                wsSettings = streamSettings.get("wsSettings", {})
                path = wsSettings.get("path", "")
                headers = wsSettings.get("headers", {})
                proxy = {
                    "name": name,
                    "type": protocol,
                    "server": server,
                    "port": port,
                    "uuid": uuid,
                    "alterId": alterId,
                    "cipher": "auto",
                    "network": network,
                    "tls": security == "tls",
                    "servername": streamSettings.get("serverName", ""),
                    "ws-opts": {
                        "path": path,
                        "headers": headers
                    }
                }
                logging.debug(f"WS Proxy: {proxy}")

        else:
            logging.warning(f"Unsupported protocol: {protocol}")

        if proxy:
            merged_proxies.append(proxy)
        else:
            logging.warning(f"No proxy configuration found for index {index}")

    except Exception as e:
        logging.error(f"Error processing xray data for index {index}: {e}")

# 添加获取物理位置函数
def get_physical_location(server):
    try:
        response = requests.get(f"https://ipinfo.io/{server}/json")
        data = response.json()
        country = data.get("country", "Unknown Country")
        city = data.get("city", "")

        # 确保返回的格式为 "US New York" 或者 "US"
        if city:
            return f"{country} {city}"
        else:
            return country
    except Exception as e:
        logging.error(f"Error fetching location for server {server}: {e}")
        return "Unknown Country"

# ... existing code ...

def update_proxy_groups(config_data, merged_proxies):
    for group in config_data['proxy-groups']:
        if group['name'] in ['自动选择', '节点选择']:
            if 'proxies' not in group or not group['proxies']:
                group['proxies'] = [proxy['name'] for proxy in merged_proxies]
            else:
                group['proxies'].extend(proxy['name'] for proxy in merged_proxies)

def update_warp_proxy_groups(config_warp_data, merged_proxies):
    for group in config_warp_data['proxy-groups']:
        if group['name'] in ['自动选择', '手动选择', '负载均衡']:
            if 'proxies' not in group or not group['proxies']:
                group['proxies'] = [proxy['name'] for proxy in merged_proxies]
            else:
                group['proxies'].extend(proxy['name'] for proxy in merged_proxies)
# Ensure merged_proxies is a global variable
merged_proxies = []

# Process the URLs
process_urls('./urls/clash_urls.txt', process_clash)
# process_urls('./urls/sb_urls.txt', process_sb)
process_urls('./urls/clashmeta.txt', process_clash)
process_urls('./urls/hysteria_urls.txt', process_hysteria)
process_urls('./urls/hysteria2_urls.txt', process_hysteria2)
process_urls('./urls/xray_urls.txt', process_xray)

# Load the templates
with open('./templates/clash_template.yaml', 'r', encoding='utf-8') as file:
    config_data = yaml.safe_load(file)

with open('./templates/clash_warp_template.yaml', 'r', encoding='utf-8') as file:
    config_warp_data = yaml.safe_load(file)

# Add merged proxies
if 'proxies' not in config_data or not config_data['proxies']:
    config_data['proxies'] = merged_proxies
else:
    config_data['proxies'].extend(merged_proxies)

if 'proxies' not in config_warp_data or not config_warp_data['proxies']:
    config_warp_data['proxies'] = merged_proxies
else:
    config_warp_data['proxies'].extend(merged_proxies)

# Update proxy groups
update_proxy_groups(config_data, merged_proxies)
update_warp_proxy_groups(config_warp_data, merged_proxies)

# Write the results to YAML files
with open('./sub/merged_proxies_new.yaml', 'w', encoding='utf-8') as file:
    yaml.dump(config_data, file, sort_keys=False, allow_unicode=True)

with open('./sub/merged_warp_proxies_new.yaml', 'w', encoding='utf-8') as file:
    yaml.dump(config_warp_data, file, sort_keys=False, allow_unicode=True)

print("聚合完成")
