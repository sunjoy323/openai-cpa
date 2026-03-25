# proxy_manager.py
import urllib.parse
import random
import time
import requests as std_requests
from datetime import datetime
import yaml
import os
import re

with open("config.yaml", "r", encoding="utf-8") as f:
    config = yaml.safe_load(f)

clash_conf = config.get("clash_proxy_pool", {})
ENABLE_NODE_SWITCH = clash_conf.get("enable", False)
CLASH_API_URL = clash_conf.get("api_url", "http://127.0.0.1:9097")
PROXY_GROUP_NAME = clash_conf.get("group_name", "节点选择")
CLASH_SECRET = clash_conf.get("secret", "")
LOCAL_PROXY_URL = clash_conf.get("test_proxy_url", "")
DEFAULT_BLACKLIST = ["港", "HK", "台", "TW", "中", "CN"]
NODE_BLACKLIST = clash_conf.get("blacklist", DEFAULT_BLACKLIST)

def ts() -> str:
    """获取当前时间戳字符串，用于日志"""
    return datetime.now().strftime("%H:%M:%S")

def test_proxy_liveness():
    """测试当前代理是否可用，并检查国家/地区归属"""
    proxies = {"http": LOCAL_PROXY_URL, "https": LOCAL_PROXY_URL}
    try:
        res = std_requests.get("https://cloudflare.com/cdn-cgi/trace", proxies=proxies, timeout=5)
        if res.status_code == 200:
            loc = "UNKNOWN"
            for line in res.text.split('\n'):
                if line.startswith("loc="):
                    loc = line.split("=")[1].strip()

            blocked_regions = ["CN", "HK"]
            if loc in blocked_regions:
                print(f"   节点能通，但 IP 归属地为受限区 ({loc})，弃用！")
                return False
                
            print(f"   节点测活成功！地区合规 ({loc})，响应延迟: {res.elapsed.total_seconds():.2f}s")
            return True
        return False
    except Exception:
        print(f"   节点无法连通外网或超时丢包。")
        return False

def smart_switch_node():
    """智能切换节点并测活的核心逻辑，支持策略组名称模糊匹配"""
    if not ENABLE_NODE_SWITCH:
        return True
        
    headers = {"Authorization": f"Bearer {CLASH_SECRET}"} if CLASH_SECRET else {}
    
    try:
        resp = std_requests.get(f"{CLASH_API_URL}/proxies", headers=headers, timeout=5)
        if resp.status_code != 200:
            print(f"[{ts()}] [ERROR] 无法连接 Clash API，请检查配置。")
            return False
            
        proxies_data = resp.json()['proxies']

        actual_group_name = None
        for key in proxies_data.keys():
            if PROXY_GROUP_NAME in key and isinstance(proxies_data[key], dict) and 'all' in proxies_data[key]:
                actual_group_name = key
                break
                
        if not actual_group_name:
            available_groups = [k for k in proxies_data.keys() if isinstance(proxies_data[k], dict) and 'all' in proxies_data[k]]
            print(f"[{ts()}] [ERROR] 找不到包含关键词 '{PROXY_GROUP_NAME}' 的策略组！")
            print(f"[{ts()}] [INFO] 当前可用的策略组有: {available_groups}")
            return False
            
        print(f"[{ts()}] [INFO] 自动匹配到真实策略组: [{clean_for_log(actual_group_name)}]")
        
        safe_group_name = urllib.parse.quote(actual_group_name)
        all_nodes = proxies_data[actual_group_name]['all']
        
        valid_nodes = [
            n for n in all_nodes 
            if not any(kw.upper() in n.upper() for kw in NODE_BLACKLIST)
        ]
        
        if not valid_nodes:
            print(f"[{ts()}] [ERROR] 过滤后没有可用安全节点！请检查 config.yaml 里的 blacklist 是否过于严格。")
            return False

        max_retries = 10
        for i in range(1, max_retries + 1):
            selected_node = random.choice(valid_nodes)
            print(f"\n[{ts()}] [INFO] [代理池] 尝试切换节点: [{clean_for_log(selected_node)}] ({i}/{max_retries})")
            switch_resp = std_requests.put(
                f"{CLASH_API_URL}/proxies/{safe_group_name}", 
                headers=headers, json={"name": selected_node}, timeout=5
            )
            
            if switch_resp.status_code == 204:
                time.sleep(1.5)
                if test_proxy_liveness():
                    return True
                # else:
                    print(f"[{ts()}] [代理池] 重新抽卡...")
            else:
                print(f"[{ts()}] [代理池] 切换指令下发失败。")
                
        print(f"\n[{ts()}] [代理池] 抽卡 10 次全败，请检查节点状态！")
        return False
    except Exception as e:
        print(f"[{ts()}] [ERROR] 节点切换异常: {e}")
        return False
def clean_for_log(text: str) -> str:
    """用于日志输出：过滤掉字符串中的国旗、飞机、火箭等 Emoji 符号"""
    emoji_pattern = re.compile(
        r'[\U0001F1E6-\U0001F1FF]'
        r'|[\U0001F300-\U0001F6FF]'
        r'|[\U0001F900-\U0001F9FF]'
        r'|[\U00002600-\U000027BF]'
        r'|[\uFE0F]'
    )
    return emoji_pattern.sub('', text).strip()