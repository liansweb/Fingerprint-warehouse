import re
import json

def parse_rule(line):
    # 使用正则表达式匹配规则的各个部分
    pattern = r'{(\d+),\s*"([^"]+)",\s*"([^"]+)",\s*"([^"]*)",\s*InStr{([^}]*)},\s*ReqHttp{([^}]*)}'
    match = re.match(pattern, line)
    
    if match:
        rank, name, type_, mode, in_str, req_http = match.groups()
        
        # 解析InStr部分
        in_str_pattern = r'"([^"]*)",\s*"([^"]*)",\s*"([^"]*)"'
        in_str_match = re.match(in_str_pattern, in_str)
        if in_str_match:
            in_body, in_header, in_ico_md5 = in_str_match.groups()
        else:
            in_body, in_header, in_ico_md5 = "", "", ""
        
        # 解析ReqHttp部分
        req_http_pattern = r'"([^"]*)",\s*"([^"]*)",\s*([^,]*),\s*"([^"]*)"'
        req_http_match = re.match(req_http_pattern, req_http)
        if req_http_match:
            req_method, req_path, req_header, req_body = req_http_match.groups()
        else:
            req_method, req_path, req_header, req_body = "", "", "nil", ""
        
        # 构建规则字典
        rule = {
            "rank": int(rank),
            "name": name,
            "type": type_,
            "mode": mode,
            "rule": {
                "inBody": in_body,
                "inHeader": in_header,
                "inIcoMd5": in_ico_md5
            },
            "http": {
                "reqMethod": req_method,
                "reqPath": req_path,
                "reqHeader": None if req_header == "nil" else req_header,
                "reqBody": req_body
            }
        }
        
        return rule
    return None

def parse_rules(file_content):
    rules = []
    for line in file_content.split('\n'):
        line = line.strip()
        if line.startswith('{') and line.endswith('},'):
            rule = parse_rule(line)
            if rule:
                rules.append(rule)
    return rules

# 读取文件内容
with open('fingerprint/dismap_rule.go', 'r', encoding='utf-8') as file:
    content = file.read()

# 解析规则
rules = parse_rules(content)

# 将规则保存为JSON文件
with open('dismap_rule.json', 'w', encoding='utf-8') as outfile:
    json.dump(rules, outfile, indent=2, ensure_ascii=False)

print("规则已保存到 dismap_rule.json 文件中。")