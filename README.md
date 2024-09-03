# fingerprint-warehouse
收集开源项目的指纹特征


## 资产识别

| 项目 | 项目名称 | 描述 | 远程文件 |
| --- | --- | --- | --- |
| [EHole_magic](https://github.com/lemonlove7/EHole_magic) | EHole(棱洞)魔改 | 漏洞指纹识别,可对路径进行指纹识别；支持识别出来的重点资产进行漏洞检测(支持从hunter和fofa中提取资产)支持对ftp服务识别及爆破  | [finger.json](https://github.com/lemonlove7/EHole_magic/blob/main/finger.json) |
| [xray-plugins-ehole](https://github.com/chaitin/xray-plugins) | xray插件 | 本仓库中的插件包括指纹、POC 以及一些指定运行的文件列表。 | [ehole](https://github.com/chaitin/xray-plugins/tree/main/finger/ehole)  |
| [xray-plugins-manual](https://github.com/chaitin/xray-plugins) | xray插件 | 本仓库中的插件包括指纹、POC 以及一些指定运行的文件列表。 | [manual](https://github.com/chaitin/xray-plugins/tree/main/finger/manual)  |
| [xray-plugins-nmap](https://github.com/chaitin/xray-plugins) | xray插件 | 本仓库中的插件包括指纹、POC 以及一些指定运行的文件列表。 | [nmap](https://github.com/chaitin/xray-plugins/tree/main/finger/nmap)  |
| [hfinger](https://github.com/HackAllSec/hfinger) | hfinger | 一个用于web框架、CDN和CMS指纹识别的高性能命令行工具。 | [finger.json](https://github.com/HackAllSec/hfinger/blob/main/data/finger.json) |
|[dismap](https://github.com/zhzyker/dismap)|dismap|dismap Asset discovery and identification tools 快速识别 Web 指纹信息，定位资产类型。辅助红队快速定位目标资产信息，辅助蓝队发现疑似脆弱点 |[rule.go](https://github.com/zhzyker/dismap/blob/main/configs/rule.go)|
|[Heimdallr](https://github.com/Ghr07h/Heimdallr)|Heimdallr|Heimdallr  一款完全被动监听的谷歌插件，用于高危指纹识别、蜜罐特征告警和拦截、机器特征对抗。|[data.js](https://github.com/Ghr07h/Heimdallr/blob/main/Heimdallr/resource/data/data.js)|
|[python-Wappalyzer](https://github.com/chorsley/python-Wappalyzer)|python-Wappalyzer|Wappalyzer |[technologies.json](https://github.com/chorsley/python-Wappalyzer/blob/master/Wappalyzer/data/technologies.json)|
|[webanalyzer](https://github.com/webanalyzer/rules)|webanalyzer|webanalyzer 是通用的指纹识别规则||
|[FingerprintHub-service-fingerprint](https://github.com/0x727/FingerprintHub)|FingerprintHub|FingerprintHub 是 侦查守卫(ObserverWard)的指纹库 |[service-fingerprint](https://github.com/0x727/FingerprintHub/tree/main/service-fingerprint)|
|[FingerprintHub-web-fingerprint](https://github.com/0x727/FingerprintHub)|FingerprintHub|FingerprintHub 是 侦查守卫(ObserverWard)的指纹库 |[web-fingerprint](https://github.com/0x727/FingerprintHub/tree/main/web-fingerprint)|
|[BBScan](https://github.com/lijiejie/BBScan/)|BBScan|BBScan  A fast vulnerability scanner helps pentesters pinpoint possibly vulnerable targets from a large number of web servers 。|[BBScan_web_fingerprint_v3.json](https://github.com/lijiejie/BBScan/blob/master/rules/web_fingerprint_v3.json)|


## poc仓库
| 项目 | 项目名称 | 描述 | 远程文件 |
| --- | --- | --- | --- |
| [xray-plugins-poc](https://github.com/chaitin/xray-plugins) | xray插件 | 本仓库中的插件包括指纹、POC 以及一些指定运行的文件列表。 | [poc](https://github.com/chaitin/xray-plugins/tree/main/poc)  |
|[POC-bomber](https://github.com/tr0uble-mAker/POC-bomber) | POC-bomber | 利用大量高威胁poc/exp快速获取目标权限，用于渗透和红队快速打点  | [POC-bomber](https://github.com/tr0uble-mAker/POC-bomber)  |




## 收集全部自动化资产收集平台
数据来源：https://redteam.wang/Quanpage/%E8%B0%83%E7%A0%94%E7%9A%84%E5%85%A8%E9%83%A8%E8%87%AA%E5%8A%A8%E5%8C%96%E8%B5%84%E4%BA%A7%E6%94%B6%E9%9B%86%E5%B9%B3%E5%8F%B0

| 链接 | 名称 |
|------|------|
| https://github.com/iSafeBlue/TrackRay | iSafeBlue/TrackRay: 溯光 (TrackRay) 3 beta⚡渗透测试框架（资产扫描|指纹识别|暴力破解|网页爬虫|端口扫描|漏洞扫描|代码审计|AWVS|NMAP|Metasploit|SQLMap） |
| https://github.com/TideSec/Mars | TideSec/Mars: Mars(战神)——资产发现、子域名枚举、C段扫描、资产变更监测、端口变更监测、域名解析变更监测、Awvs扫描、POC检测、web指纹探测、端口指纹探测、CDN探测、操作系统指纹探测、泛 |
| https://github.com/guimaizi/get_domain | guimaizi/域名收集与监测V3.0 |
| https://github.com/ysrc/GourdScanV2 | Gourdscan v2.1 被动式漏洞扫描系统 |
| https://github.com/LangziFun/BuTian_Spider | LangziFun/BuTian_Spider: 2019 补天厂商爬虫与数据可视化文件打包 |
| https://github.com/LangziFun/LangNetworkTopologys | LangNetworkTopologys: 端口扫描，指纹识别，网站探测，结果整理 |
| https://github.com/LangziFun/LangSrcCurise | LangSrcCurise: SRC子域名资产监控 |
| https://github.com/EmYiQing/Rain | EmYiQing/Rain: 漏洞扫描系统-正在更新 |
| https://github.com/carlospolop/legion | legion: Automatic Enumeration Tool based in Open Source tools |
| https://github.com/teamssix/pigat | pigat 被动信息收集聚合工具 |
| https://github.com/yogeshojha/reNgine | yogeshojha/rengine: 资产收集聚合工具 |
| https://www.freebuf.com/sectool/245292.html | reNgine：一款针对Web应用渗透测试的自动化网络侦察框架 |
| https://teamssix.com/year/200920-142641.html | reNgine 自动化网络侦查框架的国内安装与报错的解决方法 | Teams Six |
| https://github.com/OWASP/Amass | OWASP/Amass: 深度攻击面测绘和资产发现 |
| https://github.com/laramies/theHarvester | theHarvester-资产探测工具收集子域邮箱等-laramies |
| https://github.com/wgpsec/Perception | wgpsec/Perception: 基于狼组安全服务(社区)平台API打造的一款在线信息收集程序 |
| https://github.com/chaitin/xray | chaitin/xray: 一款完善的安全评估工具，支持常见 web 安全问题扫描和自定义 poc | 使用之前务必先阅读文档 |
| https://docs.xray.cool/#/guide/contribute | 贡献POC xray 安全评估工具文档 |
| https://github.com/Ascotbe/Medusa | Medusa: 漏洞扫描器、漏洞利用、子域名探测、C段扫描、资产发现、敏感信息检测等功能一体化平台。目前收录漏洞200+ http://medusa.ascotbe.com |
| https://github.com/TophantTechnology/ARL | 灯塔ARL资产侦察灯塔系统旨在快速侦察与目标关联的互联网资产，构建基础资产信息库。 协助甲方安全团队或者渗透测试人员有效侦察和检索资产，发现存在的薄弱点和攻击面。TophantTechnology/AR |
| https://github.com/phantom0301/PTscan | phantom0301/PTscan: Phantom scanner——An interface friendly and lightweight web assets scanner |
| https://github.com/crawlab-team/crawlab | crawlab: 分布式爬虫管理平台，支持任何语言和框架-crawlab-team |
| https://github.com/Echocipher/AUTO-EARN | AUTO-EARN: 自动化收集并扫描一个利用OneForAll进行子域收集、Shodan API端口扫描、Xray漏洞Fuzz、Server酱的自动化漏洞扫描、即时通知提醒的漏洞挖掘辅助工具E-chocipher |
| https://github.com/CTF-MissFeng/Watchdog | Watchdog: webWatchdog是bayonet修改版，重新优化了数据库及web及扫描程序,加入多节点-CTF-MissFeng |
| https://github.com/bit4woo/teemo | teemo-域名收集及枚举工具-bit4woo |
| https://github.com/k-fire/Url-Monitor | Url-Monitor: 基于django网站监控平台-k-fire |
| https://github.com/dyboy2017/TScan | TScan-类似潮汐-dyboy2017 |
| https://github.com/dyboy2017/WTF_Scan | dyboy2017/WTF_Scan: 一款WEB端的在线敏感资产扫描器，扫描网站中的指纹、漏洞及相关敏感信息，针对已经识别的CMS指纹，进行二次0day扫描利用，一键GetShell也不是不可能！！！ |
| https://github.com/zsdevX/DarkEye | DarkEye情报收集工具-zsdevX |
| https://github.com/HatBoy/Awheel | Awheel: 分布式信息收集工-HatBoy |
| https://github.com/kelvinBen/AppInfoScanner | AppInfoScanner-移动端程序信息收集工具-kelvinBen |
| https://github.com/projectdiscovery | ProjectDiscovery开源资产搜集集合未看完 |
| https://github.com/ixiaofeng/crazyDhtSpider | DHT爬虫ixiaofeng/crazyDhtSpider: 依托于swoole的PHP版本的DHT爬虫，磁力搜索站必备，有着奇高的效率。 |
| https://github.com/aeverj/weblive | weblive:批量主机存活测试 批量获取网站基本信息-aeverj |
| https://github.com/Cl0udG0d/HXnineTails#部分截图 | HXnineTails-多工具集成器-Cl0udG0d |
| https://github.com/hakluke/hakrawler | hakrawler: Go Web爬虫，Web资产发现-hakluke |
| https://github.com/shadow1ng/ProxyPool | ProxyPool: 自动切换ip的代理池服务,无需任何依赖-shadow1ng |
| https://github.com/s0md3v/Diggy | Diggy: apk信息收集提取信息工具-s0md3v |
| https://github.com/0xPwny/Apkatshu | Apkatshu: APK分析工具-0xPwny |
| https://github.com/CTF-MissFeng/GoScan | GoScan:web综合资产管理系统，适合红队、SRC等使用-CTF-MissFeng |
| https://admin-root.blog.csdn.net/article/details/110357936 | github敏感信息搜集工具gsil的配置及使用_爱国小白帽-CSDN博客 |
| https://github.com/thunderbarca/Caesar | Caesar-一个全新的敏感文件发现工具-thunderbarca |
| https://github.com/ShiHuang-ESec/EHole | EHole: EHole(棱洞)-指纹状态码title红队重点攻击系统指纹探测工具ShiHuang-ESec |
| https://github.com/NetSPI/NetblockTool | NetblockTool：查找公司拥有的网络块 不知道咋样-NetSPI |
| https://github.com/swisskyrepo/DamnWebScanner | DamnWebScanner:类似xray结合burp-swisskyrepo |
| https://github.com/w-digital-scanner/w13scan | w13scan: (被动式安全扫描器) |
| https://github.com/w-digital-scanner/w12scan | w-digital-scanner/w12scan: 🚀 A simple asset discovery engine for cybersecurity. (网络资产发现引擎) |
| https://github.com/w-digital-scanner/w10scan | w-digital-scanner/w10scan: 全自动搜索互联网漏洞 |
| https://www.aisec.com/aiscanner/login.php?msg=请先登录&t=160051722 | ALScanner 安全检测系统 |
| https://github.com/s7ckTeam/Glass | Glass快速批量指纹识别工具-s7ckTeam |
| https://github.com/c1y2m3/Subatk | c1y2m3/Subatk: Sublist3r优化版,添加web可视化页面以及masscan端口扫描 |
| https://github.com/h4ckdepy/bayonet | h4ckdepy/bayonet: bayonet是一款src资产管理系统，从子域名、端口服务、漏洞、爬虫等一体化的资产管理系统 |
| https://github.com/WyAtu/Perun | WyAtu/Perun: Perun资产探测&漏洞扫描器，可用于内网是一款主要适用于乙方安服、渗透测试人员和甲方RedTeam红队人员的网络资产漏洞扫描器/扫描框架 |
| https://www.uedbox.com/post/55315/ | Netsparker pro V5.3破解版，Web安全扫描器 体验盒子 关注网络安全 |
| https://github.com/sv3nbeast/X-AutoXray | X-AutoXray: AutoScan 有多个目标时，调用xray+rad进行自动扫描-sv3nbeast |
| https://github.com/k-fire/fofa-tool | fofa-tool: 批量提取fofa查询-k-fire |
| https://github.com/timwhitez/crawlergo_x_XRAY | timwhitez/crawlergo_x_XRAY: 360/0Kee-Team/crawlergo动态爬虫结合长亭XRAY扫描器的被动扫描功能 |
| https://github.com/timwhitez/Frog-Fp | Frog-Fp: 🐸批量深度指纹识别框架-timwhitez |
| https://github.com/madneal/gshark | gshark-轻松有效地扫描敏感信息-madneal |
| https://github.com/Cl0udG0d/SZhe_Scan | SZhe_Scan-有web端碎遮SZhe_Scan Web漏洞扫描器，基于python Flask框架，对输入的域名/IP进行全面的信息搜集，漏洞扫描，可自主添加POC-Cl0udG0d |
| https://github.com/Cl0udG0d/HXnineTails | HXnineTails: python3实现的集成了github上多个扫描工具的命令行WEB扫描工具-Cl0udG0d |
| https://github.com/sensepost/gowitness | gowitness-一个golang, web截图工具-sensepost |
| https://github.com/Cl0udG0d/pppXray | pppXrayXray批量化自动扫描-Cl0udG0d |
| https://github.com/naozibuhao/SecurityManageFramwork | naozibuhao/SecurityManageFramwork |
| https://github.com/projectdiscovery/subfinder | subfinder子域名查找工具,可以自行配置API接口，获取更多更全面的子域名-projectdiscovery |
| https://github.com/taomujian/linbing | taomujian/linbing: 漏洞扫描系统本系统是对目标进行漏洞扫描的一个系统,前端采用vue技术,后端采用flask.核心原理是扫描主机的开放端口情况,然后根据端口情况逐个去进行poc检测,poc有110多个,包含绝 |
| https://github.com/projectdiscovery/httpx | httpx快速获取域名标题、状态码、响应大小等等信息-projectdiscovery |
| https://github.com/projectdiscovery/naabu | naabu一个快速端口扫描仪-projectdiscovery |
| https://github.com/jiangsir404/POC-S | jiangsir404/POC-S: POC-T强化版本 POC-S -批量漏洞验证框架, 用于红蓝对抗中快速验证Web应用漏洞， 对功能进行强化以及脚本进行分类添加，自带dnslog等, 平台补充来自vulhub靶机及其他开源项目的高可 |
| https://github.com/er10yi/MagiCude | er10yi/MagiCude: 分布式端口（漏洞）扫描、资产安全管理、实时威胁监控与通知、高效漏洞闭环、漏洞wiki、邮件报告通知、poc框架 |
| https://github.com/Power7089/PenetrationTest-Tips | PenetrationTest-Tips-渗透测试姿势持续更新，渗透测试小技巧，渗透测试Tips-Power7089 |
| https://github.com/TideSec/FuzzScanner | TideSec/FuzzScanner: 一个主要用于信息搜集的工具集，主要是用于对网站子域名、开放端口、端口指纹、c段地址、敏感目录等信息进行批量搜集。 |
| https://github.com/test502git/awvs13_batch_py3 | awvs13_batch_py3-针对 AWVS扫描器开发的批量扫描脚本，支持联动xray、burp、w13scan等被动批量-test502git |
| https://github.com/JKme/xscan | JKme/xscan: 代码垃圾的缝合怪扫描器 |
| https://github.com/al0ne/Vxscan | Vxscan-python3写的综合扫描工具-轮子组合怪-al0ne |
| https://github.com/wgpsec/IGScan | wgpsec/IGScan: WgpSec Team IGScan 一款信息收集工具 |
| https://github.com/canc3s/cSubsidiary | cSubsidiary-利用天眼查查询企业子公司-canc3s |
| https://github.com/canc3s/cDomain | cDomain-利用天眼查查询企业备案-canc3s |
| https://github.com/Mr-xn/subdomain_shell | subdomain_shell三个工具集合-子域名标题状态码收集subdomain_shell: 一键调用subfinder+ksubdomain+httpx 强强联合 从域名发现-->域名验证-->获取域名标题、状态码以及响应大小 最后保存结果,简化重复操作 |
| https://github.com/bit4woo/domain_hunter_pro | domain_hunter_proburp插件 SRC挖洞、HW打点之必备！自动化资产收集；快速Title获取；外部工具联动-bit4woo |
| https://github.com/lcvvvv/kscan | kscan-拼接多个工具的轮子-子域端口banner一键化-lcvvvv |
| https://github.com/tomnomnom/assetfinder | assetfinder-查找与给定域相关的域和子域-tomnomnom |
| https://github.com/r3curs1v3-pr0xy/vajra | vajra：Vajra是一个高度可定制的基于目标和范围的自动Web黑客框架，可在Web应用程序渗透测试期间自动执行无聊的侦察任务和对多个目标的相同扫-r3curs1v3-pr0xy |
| https://github.com/jaeles-project/gospider | Gospider-用Go语言编写的快速网络爬虫-爬取url-jaeles-project |
| https://github.com/Miagz/XrayFofa | XrayFofa-将xray和fofa完美结合的自动化工具,调用fofaAPI进行查询扫描,新增爬虫爬取扫描-Miagz |
| https://github.com/TeraSecTeam/ary | TeraSecTeam/ary: Ary 是一个集成类工具，主要用于调用各种安全工具，从而形成便捷的一键式渗透。 |
| https://github.com/wgpsec/DBJ | wgpsec/DBJ: 大宝剑-信息收集和资产梳理工具（红队、蓝队、企业组织架构、子域名、Web资产梳理、Web指纹识别、ICON_Hash资产匹配） |
| https://github.com/admintony/Digger | Digger-子域名收集工具从百度爬取子域名-admintony |
| https://github.com/wgpsec/ENScan | ENScan-基于爱企查的一款企业信息查询工具-wgpsec |
| https://github.com/xundididi/Voyager | xundididi/Voyager: 一个安全工具集合平台，用来提高乙方安全人员的工作效率，请勿用于非法项目 |
| https://github.com/zhzyker/vulmap | Vulmap是一款漏洞扫描工具，可对Web容器、Web服务器、Web中间件以及CMS等Web程序进行漏洞扫描，并且具备漏洞利用功能。 相关测试人员可以使用vulmap检测目标是否存在特定漏洞，并且可以使用漏 |
| https://github.com/TheKingOfDuck/ApkAnalyser | ApkAnalyser-一键提取安卓应用中可能存在的敏感信息。-TheKingOfDuck |
| https://github.com/s7ckTeam/Glass | Glass针对资产列表的快速指纹识别工具-s7ckTeam |
| https://github.com/78778443/QingScan | QingScan-一个漏洞扫描器粘合剂；支持 web扫描、系统扫描、子域名收集、目录扫描、主机扫描、主机发现、组件识别、URL爬虫、XRAY扫描、AWVS自动扫描、POC批量验证，SSH批量测试、vulmap-78778443 |
| https://github.com/hanc00l/nemo_go | hanc00l/nemo_go: Nemo是用来进行自动化信息收集的一个简单平台，通过集成常用的信息收集工具和技术，实现对内网及互联网资产信息的自动收集，提高隐患排查和渗透测试的工作效率，用Go语言完全重构了原Python版本。 |
| https://github.com/Goqi/Banli | Goqi/Banli: Banli-高危资产识别和高危漏洞扫描工具 |
| https://github.com/ExpLangcn/FuYao | ExpLangcn/FuYao: FuYao 扶摇直上九万里！自动化进行资产探测及漏洞扫描｜适用黑客进行赏金活动、SRC活动、大规模攻击使用 |
| https://github.com/tr0uble-mAker/POC-bomber | POC-bomber-poc验证利用大量高威胁poc-exp快速获取目标权限，用于渗透和红队快速打点-tr0uble-mAker |
| https://github.com/b0bac/ApolloScanner | ApolloScanner-缺POC自动化巡航扫描框架（可用于红队打点评估）-b0bac |
| https://github.com/awake1t/linglong | linglong-调用xraypoc的漏扫可收集自产和爆破-awake |
| https://github.com/d3ckx1/Fvuln | Fvuln-存活探测，poc扫描，弱口令爆破-d3ckx1 |



## 免责声明

本仓库收集的开源项目指纹特征仅用于安全研究和教育目的，任何个人和组织在使用这些指纹特征时必须遵守相关法律法规，并确保不会用于任何非法用途。我们不对任何个人或组织使用本仓库内容造成的任何后果承担责任。