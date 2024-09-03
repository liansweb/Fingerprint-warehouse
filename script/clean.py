import json
import os
import re

def clean_fingerprints(input_dir, output_file):
    cleaned_fingerprints = []

    for filename in os.listdir(input_dir):
        if filename.endswith('.js') or filename.endswith('.json'):
            with open(os.path.join(input_dir, filename), 'r', encoding='utf-8') as f:
                content = f.read()
                
            if filename.endswith('.js'):
                # 处理 Heimdallr.js
                matches = re.findall(r'{[\s\S]*?}', content)
                for match in matches:
                    try:
                        rule = eval(match)
                        cleaned_rule = {
                            'name': rule.get('commandments', ''),
                            'type': 'body' if rule.get('ruleposition') in [1, 3, 5] else 'header',
                            'method': 'keyword',
                            'rule': str(rule.get('rulecontent', ''))
                        }
                        cleaned_fingerprints.append(cleaned_rule)
                    except:
                        pass
            else:
                # 处理 JSON 文件
                data = json.loads(content)
                if 'finger' in data:
                    for finger in data['finger']:
                        cleaned_rule = {
                            'name': finger.get('cms', ''),
                            'type': finger.get('location', ''),
                            'method': finger.get('method', ''),
                            'rule': finger.get('rule', [])
                        }
                        cleaned_fingerprints.append(cleaned_rule)

    # 写入清洗后的数据
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(cleaned_fingerprints, f, ensure_ascii=False, indent=2)

def convert_to_template(input_file, output_file, template):
    with open(input_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    converted_data = []
    for item in data:
        new_item = template.copy()
        for key, value in item.items():
            if key in new_item:
                new_item[key] = value
        converted_data.append(new_item)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(converted_data, f, ensure_ascii=False, indent=2)

# 使用示例
input_dir = 'fingerprint'
cleaned_file = 'cleaned_fingerprints.json'
template_file = 'template_fingerprints.json'

# 清洗指纹
clean_fingerprints(input_dir, cleaned_file)

# 定义模板
template = {
    "name": "",
    "type": "",
    "method": "",
    "rule": "",
    "additional_field": ""
}

# 根据模板转换
convert_to_template(cleaned_file, template_file, template)