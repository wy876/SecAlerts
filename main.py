# main.py (优化版 - 紧凑布局)

import os
import re
import sys
import json
import time
import xml.etree.ElementTree as ET
import datetime
import requests
import glob
from collections import defaultdict, Counter

# --- 全局配置 ---
ARCHIVE_DIR = 'archive'
RECENT_DAYS = 7 # 首页显示最近N天的文章

# --- 漏洞文章关键词（统一配置，全部用 re.I 忽略大小写，cve / Cve / CVE 均可命中）---
KEYWORD_PATTERN = re.compile(
    r'('
    # 漏洞编号
    r'CVE-\d+|CNVD-[\w-]+|CNNVD-[\w-]+|CNVD|CNNVD|XVE-[\w-]+|QVD-[\w-]+|GHSA-[\w-]+|'
    # 通用
    r'复现|漏洞|预警|通告|风险通告|安全公告|在野|0click|0day|1day|nday|POC|EXP|payload|'
    # 远程/命令执行
    r'RCE|远程代码执行|任意代码执行|代码执行|命令执行|命令注入|'
    # 注入类
    r'SQL注入|SQLi|注入|XSS|跨站|CSRF|SSRF|XXE|模板注入|SSTI|'
    # 反序列化 / 内存马
    r'反序列化|内存马|JNDI|fastjson|log4j|shiro|'
    # 权限类
    r'未授权|越权|提权|权限绕过|授权绕过|认证绕过|鉴权绕过|逻辑漏洞|'
    # 文件类
    r'任意文件读取|任意文件写入|任意文件上传|任意文件下载|文件上传|文件包含|文件读取|目录穿越|路径穿越|目录遍历|'
    # 利用产物
    r'getshell|webshell|哥斯拉|冰蝎|后门|供应链|沙箱逃逸|横向移动|'
    # 其他
    r'信息泄露|敏感信息|硬编码|弱口令|代码审计|渗透'
    r')',
    re.I
)

# --- 健壮的网络请求函数 (无变化) ---
def robust_get(url, headers, timeout=30, retries=3, delay=5, stream=False):
    for i in range(retries + 1):
        try:
            response = requests.get(url, headers=headers, timeout=timeout, stream=stream)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            if i < retries:
                print(f"[!] 请求失败: {str(e)[:100]}. {delay}秒后重试 ({i+1}/{retries})... URL: {url}")
                time.sleep(delay)
            else:
                print(f"[-] 所有重试均失败: {url}")
                return None

# --- JSON 读写和持久化函数 (无变化) ---
def write_json(path, data, encoding="utf8"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding=encoding) as f:
        json.dump(data, f, ensure_ascii=False, indent=4)

def read_json(path, default_data=[], encoding="utf8"):
    if os.path.exists(path):
        try:
            with open(path, "r", encoding=encoding) as f:
                return json.load(f)
        except (json.JSONDecodeError, UnicodeDecodeError):
            print(f"[-] {path} 文件格式错误或为空，将使用默认值。")
            return default_data
    return default_data

def read_all_articles_from_archive():
    all_articles = []
    json_files = glob.glob(os.path.join(ARCHIVE_DIR, '**', '*.json'), recursive=True)
    for file_path in json_files:
        daily_articles = read_json(file_path)
        if isinstance(daily_articles, list):
            all_articles.extend(daily_articles)
    print(f"[*] 从 archive 目录加载了 {len(all_articles)} 篇历史文章元数据。")
    return all_articles

def save_daily_articles(articles, target_date):
    if not articles: return
    year_str = target_date[:4]
    file_path = os.path.join(ARCHIVE_DIR, year_str, f"{target_date}.json")
    existing_articles = read_json(file_path)
    existing_urls = {article['url'] for article in existing_articles}
    articles_to_add = [art for art in articles if art['url'] not in existing_urls]
    if articles_to_add:
        updated_articles = existing_articles + articles_to_add
        write_json(file_path, updated_articles)
        print(f"[+] {len(articles_to_add)} 篇新文章元数据已保存到 {file_path}")

# --- 信息源获取函数 (无变化) ---
def get_articles_from_picker_content(content, source_name):
    articles = []
    link_pattern = r'\[(.*?)\]\((https://mp\.weixin\.qq\.com/.*?)\)'
    for line in content.splitlines():
        if KEYWORD_PATTERN.search(line):
            match = re.search(link_pattern, line)
            if match:
                title, url = match.group(1).strip(), match.group(2).strip().rstrip(')')
                if title and url:
                    articles.append({'title': title, 'url': url, 'source': source_name})
    return articles

def fetch_picker_articles_with_fallback(repo_path, source_name, target_date):
    file_path = f"archive/daily/{target_date[:4]}/{target_date}.md"
    url = f"https://raw.githubusercontent.com/{repo_path}/master/{file_path}"
    headers = {'user-agent': 'Mozilla/5.0'}
    print(f"[*] 正在从 {source_name} 获取 {target_date} 的日报...")
    print(f"    -> 尝试地址: {url}")
    response = robust_get(url, headers=headers)
    if response:
        articles = get_articles_from_picker_content(response.text, source_name)
        if articles:
            print(f"    [+] 成功从 {url} 获取 {len(articles)} 篇文章链接。")
            return articles
    print(f"[-] 从 {source_name} 获取 {target_date} 的文章失败。")
    return []

def get_chainreactors_articles(target_date): return fetch_picker_articles_with_fallback("chainreactors/picker", "ChainReactors", target_date)
def get_BruceFeIix_articles(target_date): return fetch_picker_articles_with_fallback("BruceFeIix/picker", "BruceFeIix", target_date)

def get_doonsec_articles():
    rss_url = 'https://wechat.doonsec.com/rss.xml'
    headers = {'user-agent': 'Mozilla/5.0'}
    print(f"[*] 正在从 Doonsec RSS 获取最新日报...")
    response = robust_get(rss_url, headers)
    if not response: return []
    articles = []
    try:
        response.encoding = response.apparent_encoding
        root = ET.fromstring(response.text)
        for item in root.findall('./channel/item'):
            title, link = (item.findtext('title') or '').strip(), (item.findtext('link') or '').strip()
            if KEYWORD_PATTERN.search(title) and link.startswith('https://mp.weixin.qq.com/'):
                articles.append({'title': title, 'url': link.rstrip(')'), 'source': 'Doonsec'})
        print(f"[+] 成功从 Doonsec RSS 解析到 {len(articles)} 篇文章链接。")
        return articles
    except Exception as e:
        print(f"[-] 解析 Doonsec RSS 失败: {e}")
        return []

def get_mrxn_articles():
    """从 MRXN RSS 获取最新安全文章"""
    rss_url = 'https://mrxn.net/rss.php'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Accept-Language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
    }
    print(f"[*] 正在从 MRXN RSS 获取最新文章...")
    response = robust_get(rss_url, headers)
    if not response: return []

    articles = []
    # MRXN 的文章标题质量较高，可以直接使用，无需关键词过滤，以收录更全面的内容
    # 如果需要过滤，把下面 if 判断里的 True 换成 KEYWORD_PATTERN.search(title)
    try:
        response.encoding = response.apparent_encoding
        root = ET.fromstring(response.text)
        for item in root.findall('./channel/item'):
            title = (item.findtext('title') or '').strip()
            link = (item.findtext('link') or '').strip()

            # MRXN 的链接多样，不需要过滤微信链接，只要标题和链接存在即可
            # 如需按关键词过滤，把下面的 True 换成 KEYWORD_PATTERN.search(title)
            if title and link and True:
                articles.append({'title': title, 'url': link, 'source': 'MRXN'})

        print(f"[+] 成功从 MRXN RSS 解析到 {len(articles)} 篇文章链接。")
        return articles
    except Exception as e:
        print(f"[-] 解析 MRXN RSS 失败: {e}")
        return []

def get_issue_articles():
    file_path = os.getenv('ISSUE_CONTENT_PATH', '/tmp/issue_content.txt')
    articles = []
    if os.path.exists(file_path):
        print(f"[*] 正在从 issue 文件 {file_path} 获取链接...")
        content = open(file_path, 'r', encoding='utf8').read()
        urls = re.findall(r'(https://mp.weixin.qq.com/[^\s)]+)', content, re.I)
        for url in urls:
            articles.append({'title': f"来自Issue的链接-{url[:50]}...", 'url': url.rstrip(')'), 'source': 'GitHub Issue'})
    return articles

# --- HTML 渲染辅助函数 ---
import html as _html

# 漏洞编号：CVE/CNVD/CNNVD/XVE/QVD/GHSA 等
_CVE_RE = re.compile(r'(CVE-\d{4}-\d+|CNVD-[\w-]+|CNNVD-[\w-]+|XVE-[\w-]+|QVD-[\w-]+|GHSA-[\w-]+)', re.I)
# 高危关键词
_CRIT_RE = re.compile(
    r'(远程代码执行|任意代码执行|代码执行|命令执行|命令注入|RCE|0day|0click|1day|nday|POC|EXP|'
    r'反序列化|内存马|SQL注入|SQLi|SSRF|XXE|SSTI|XSS|CSRF|'
    r'未授权|越权|提权|权限绕过|授权绕过|认证绕过|鉴权绕过|'
    r'任意文件读取|任意文件写入|任意文件上传|任意文件下载|文件上传|文件包含|目录穿越|路径穿越|目录遍历|'
    r'getshell|webshell|后门|供应链|沙箱逃逸|弱口令|信息泄露|代码审计|复现)',
    re.I
)

def highlight_title(title):
    """对标题做 HTML 转义，并高亮漏洞编号与高危关键词。"""
    safe = _html.escape(title or '无标题')
    safe = _CVE_RE.sub(lambda m: f'<span class="kw kw-cve">{m.group(0)}</span>', safe)
    safe = _CRIT_RE.sub(lambda m: f'<span class="kw kw-crit">{m.group(0)}</span>', safe)
    return safe

def source_class(source):
    """把来源名转换成 CSS class，未知来源用默认色。"""
    key = re.sub(r'[^a-z0-9]', '', (source or '').lower())
    known = {'doonsec', 'chainreactors', 'brucefeiix', 'mrxn', 'githubissue'}
    return f"src-{key}" if key in known else "src-default"

# 客户端实时搜索脚本（作为 format 的插入值，内部花括号无需转义）
SEARCH_SCRIPT = """
    <script>
    (function () {
        const input = document.getElementById('searchInput');
        const info = document.getElementById('searchInfo');
        const noResult = document.getElementById('noResult');
        const groups = Array.from(document.querySelectorAll('.articles-container details'));
        // 预存每条文章的纯文本（标题 + 来源），加速匹配
        const items = [];
        groups.forEach(function (d) {
            d.querySelectorAll('li').forEach(function (li) {
                const a = li.querySelector('a');
                const tag = li.querySelector('.source-tag');
                items.push({
                    li: li,
                    group: d,
                    text: ((a ? a.textContent : '') + ' ' + (tag ? tag.textContent : '')).toLowerCase()
                });
            });
        });
        const defaultOpen = groups.map(function (d) { return d.open; });

        function debounce(fn, ms) {
            let t;
            return function () { clearTimeout(t); t = setTimeout(fn, ms); };
        }

        function reset() {
            items.forEach(function (it) { it.li.style.display = ''; });
            groups.forEach(function (d, i) { d.style.display = ''; d.open = defaultOpen[i]; });
            info.textContent = '';
            noResult.style.display = 'none';
        }

        function run() {
            const q = input.value.trim().toLowerCase();
            if (!q) { reset(); return; }
            const keywords = q.split(/\\s+/).filter(Boolean);
            const counts = new Map();
            let total = 0;
            items.forEach(function (it) {
                const hit = keywords.every(function (k) { return it.text.indexOf(k) !== -1; });
                it.li.style.display = hit ? '' : 'none';
                if (hit) {
                    total++;
                    counts.set(it.group, (counts.get(it.group) || 0) + 1);
                }
            });
            groups.forEach(function (d) {
                const c = counts.get(d) || 0;
                d.style.display = c ? '' : 'none';
                d.open = c > 0;
            });
            info.textContent = '找到 ' + total + ' 篇';
            noResult.style.display = total ? 'none' : 'block';
        }

        input.addEventListener('input', debounce(run, 120));
        input.addEventListener('keydown', function (e) {
            if (e.key === 'Escape') { input.value = ''; reset(); }
        });
    })();
    </script>
"""

# --- HTML主页生成函数 (仪表盘双栏布局) ---
def generate_html_page(articles, output_path, page_title, nav_link_html):
    """
    生成一个仪表盘式双栏聚合页面：顶部概览 + 左侧导航 + 右侧文章流。
    """
    print(f"[*] 正在生成页面: {output_path}...")

    grouped_articles = defaultdict(list)
    source_counts = Counter()
    risk_counts = Counter()
    for article in articles:
        date = article.get('date_added', '未知日期')
        grouped_articles[date].append(article)
        source_counts[article.get('source', '未知')] += 1
        title = article.get('title', '')
        if _CVE_RE.search(title):
            risk_counts['漏洞编号'] += 1
        if _CRIT_RE.search(title):
            risk_counts['高危关键词'] += 1

    sorted_dates = sorted(grouped_articles.keys(), reverse=True)
    today_str = datetime.datetime.now().strftime("%Y-%m-%d")
    total_articles = len(articles)
    total_days = len(sorted_dates)
    top_source, top_source_count = ('暂无', 0)
    if source_counts:
        top_source, top_source_count = source_counts.most_common(1)[0]

    html_template = """
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>安全文章聚合</title>
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=Noto+Serif+SC:wght@400;700&family=Poppins:wght@600;700&display=swap" rel="stylesheet">
        <style>
            :root {{
                --bg: #eef3f8;
                --panel: #fff;
                --soft: #f8fafc;
                --text: #1f2a37;
                --muted: #7b8794;
                --line: #e5edf5;
                --blue: #0b74de;
                --blue-soft: #e7f2ff;
            }}
            * {{ box-sizing: border-box; }}
            html {{ scroll-behavior: smooth; }}
            body {{
                margin: 0;
                min-height: 100vh;
                font-family: 'Noto Serif SC', serif;
                font-size: 15px;
                line-height: 1.75;
                color: var(--text);
                background:
                    radial-gradient(circle at 12% 12%, rgba(11,116,222,.14), transparent 30%),
                    radial-gradient(circle at 90% 8%, rgba(249,115,22,.12), transparent 28%),
                    var(--bg);
            }}
            .page-shell {{ width: min(1480px, calc(100% - 32px)); margin: 0 auto; padding: 28px 0 36px; }}
            .hero {{
                display: grid;
                grid-template-columns: minmax(0,1fr) auto;
                gap: 22px;
                align-items: end;
                padding: 30px;
                border: 1px solid rgba(255,255,255,.75);
                border-radius: 28px;
                background: linear-gradient(135deg, rgba(255,255,255,.94), rgba(247,250,253,.88));
                box-shadow: 0 24px 70px rgba(25,42,70,.10);
                backdrop-filter: blur(14px);
            }}
            .eyebrow {{
                display: inline-flex;
                align-items: center;
                gap: 8px;
                margin-bottom: 8px;
                color: var(--blue);
                font-family: 'Poppins','Noto Serif SC',sans-serif;
                font-size: .78em;
                font-weight: 700;
                letter-spacing: .12em;
                text-transform: uppercase;
            }}
            .eyebrow::before {{ content: ''; width: 9px; height: 9px; border-radius: 99px; background: #0f9f6e; box-shadow: 0 0 0 6px rgba(15,159,110,.12); }}
            h1 {{ margin: 0; font-family: 'Poppins','Noto Serif SC',sans-serif; font-size: clamp(2.1rem,5vw,4.8rem); line-height: 1.02; letter-spacing: -.06em; color: #102033; }}
            .hero-subtitle {{ max-width: 760px; margin: 16px 0 0; color: #5f6f82; font-size: 1.02em; }}
            .meta {{ color: var(--muted); }}
            .hero-actions {{ display: flex; flex-direction: column; align-items: flex-end; gap: 12px; }}
            .nav a {{ display: inline-flex; align-items: center; justify-content: center; min-height: 42px; padding: 8px 18px; border-radius: 999px; background: #102033; color: #fff; text-decoration: none; font-weight: 700; box-shadow: 0 12px 28px rgba(16,32,51,.18); }}
            .nav a:hover {{ transform: translateY(-1px); }}
            .stat-grid {{ display: grid; grid-template-columns: repeat(4,minmax(0,1fr)); gap: 14px; margin: 18px 0; }}
            .stat-card {{ min-height: 118px; padding: 18px; border: 1px solid rgba(255,255,255,.78); border-radius: 22px; background: rgba(255,255,255,.88); box-shadow: 0 16px 40px rgba(25,42,70,.08); }}
            .stat-label {{ color: var(--muted); font-size: .82em; font-weight: 700; }}
            .stat-value {{ margin-top: 8px; font-family: 'Poppins','Noto Serif SC',sans-serif; font-size: clamp(1.8rem,4vw,2.9rem); font-weight: 700; line-height: 1; color: #102033; }}
            .stat-note {{ margin-top: 8px; color: #8190a3; font-size: .82em; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
            .dashboard {{ display: grid; grid-template-columns: 300px minmax(0,1fr); gap: 18px; align-items: start; }}
            .sidebar {{ position: sticky; top: 16px; max-height: calc(100vh - 32px); overflow: auto; padding: 18px; border: 1px solid rgba(255,255,255,.78); border-radius: 26px; background: rgba(255,255,255,.9); box-shadow: 0 18px 48px rgba(25,42,70,.09); }}
            .side-section + .side-section {{ margin-top: 22px; }}
            .side-title {{ margin: 0 0 12px; color: #102033; font-family: 'Poppins','Noto Serif SC',sans-serif; font-size: .86em; font-weight: 700; letter-spacing: .06em; text-transform: uppercase; }}
            .date-nav {{ display: grid; gap: 8px; }}
            .date-link {{ display: grid; grid-template-columns: 1fr auto; gap: 10px; align-items: center; padding: 10px 12px; border-radius: 16px; color: #415168; text-decoration: none; background: var(--soft); border: 1px solid transparent; }}
            .date-link:hover, .date-link.is-today {{ border-color: #b9dbff; background: var(--blue-soft); color: #0b5cad; }}
            .date-count {{ font-family: 'Poppins',sans-serif; font-size: .78em; font-weight: 700; color: var(--muted); }}
            .source-list {{ display: grid; gap: 9px; }}
            .source-row {{ display: flex; align-items: center; justify-content: space-between; gap: 10px; color: #526173; font-size: .92em; }}
            .source-row .name {{ display: flex; align-items: center; min-width: 0; }}
            .source-row .count {{ font-family: 'Poppins',sans-serif; font-weight: 700; }}
            .source-dot {{ width: 9px; height: 9px; margin-right: 8px; border-radius: 99px; background: #adb5bd; display: inline-block; }}
            .src-dot-doonsec {{ background: #4dabf7; }} .src-dot-chainreactors {{ background: #845ef7; }} .src-dot-brucefeiix {{ background: #20c997; }} .src-dot-mrxn {{ background: #ff922b; }} .src-dot-githubissue {{ background: #495057; }}
            .content-panel {{ min-width: 0; }}
            .search-box {{ position: sticky; top: 16px; z-index: 20; display: flex; align-items: center; gap: 12px; padding: 14px; margin-bottom: 18px; border: 1px solid rgba(255,255,255,.82); border-radius: 24px; background: rgba(255,255,255,.94); box-shadow: 0 16px 42px rgba(25,42,70,.09); backdrop-filter: blur(16px); }}
            #searchInput {{ flex: 1 1 auto; width: 100%; min-height: 46px; padding: 0 18px; border: 1px solid var(--line); border-radius: 16px; font-family: inherit; font-size: 1em; color: #243447; outline: none; background: var(--soft); transition: border-color .25s ease, box-shadow .25s ease, background .25s ease; }}
            #searchInput:focus {{ border-color: var(--blue); background: #fff; box-shadow: 0 0 0 4px rgba(11,116,222,.12); }}
            #searchInput::placeholder {{ color: #9aa7b6; }}
            .search-info {{ flex: 0 0 auto; padding: 0 12px; color: #0b5cad; font-weight: 700; white-space: nowrap; }}
            .search-no-result {{ text-align: center; padding: 50px 0; color: #9aa7b6; font-size: 1.05em; }}
            mark.search-hit {{ background: #ffe066; color: #5c3c00; padding: 0 2px; border-radius: 3px; }}
            .articles-container {{ display: grid; gap: 18px; }}
            details {{ overflow: hidden; border: 1px solid rgba(255,255,255,.82); border-radius: 26px; background: rgba(255,255,255,.92); box-shadow: 0 18px 48px rgba(25,42,70,.08); scroll-margin-top: 96px; }}
            summary {{ display: flex; align-items: center; gap: 14px; padding: 18px 22px; cursor: pointer; outline: none; background: linear-gradient(90deg,#fff,#f7fbff); }}
            summary::-webkit-details-marker {{ display: none; }}
            summary::before {{ content: '⌄'; display: inline-grid; place-items: center; width: 30px; height: 30px; border-radius: 12px; background: var(--blue-soft); color: var(--blue); font-family: 'Poppins',sans-serif; font-weight: 700; transition: transform .25s ease; }}
            details:not([open]) > summary::before {{ transform: rotate(-90deg); }}
            summary h2 {{ margin: 0; font-family: 'Poppins','Noto Serif SC',sans-serif; font-size: 1.24em; letter-spacing: -.02em; }}
            .today h2 {{ color: var(--blue); }}
            .count-badge {{ margin-left: auto; padding: 4px 12px; border-radius: 999px; background: var(--blue-soft); color: #0b5cad; font-family: 'Poppins',sans-serif; font-size: .78em; font-weight: 700; }}
            .today .count-badge {{ background: var(--blue); color: #fff; }}
            ul {{ list-style: none; display: grid; grid-template-columns: repeat(auto-fit,minmax(320px,1fr)); gap: 12px; margin: 0; padding: 0 18px 20px; }}
            li {{ display: grid; grid-template-columns: auto minmax(0,1fr); grid-template-areas: 'idx title' 'idx source'; column-gap: 14px; row-gap: 12px; padding: 18px 20px; border: 1px solid var(--line); border-radius: 20px; background: linear-gradient(180deg,#fff,#fbfdff); transition: transform .2s ease, border-color .2s ease, box-shadow .2s ease; }}
            li:hover {{ transform: translateY(-3px); border-color: #badcff; box-shadow: 0 16px 34px rgba(25,42,70,.10); }}
            li .idx {{ grid-area: idx; display: inline-grid; place-items: center; width: 34px; height: 34px; border-radius: 14px; background: #eef4fb; color: #8a98aa; font-family: 'Poppins',sans-serif; font-size: .82em; font-weight: 700; }}
            li .article-main {{ grid-area: title; min-width: 0; }}
            li a {{ color: #0f1d2f; text-decoration: none; font-weight: 700; font-size: 1.12em; line-height: 1.55; letter-spacing: -.01em; }}
            li a:hover {{ color: var(--blue); text-decoration: underline; }}
            li a:visited {{ color: #4a5b70; }}
            .kw {{ display: inline-block; padding: 0 6px; margin: 0 1px; border-radius: 7px; font-size: .82em; font-weight: 700; vertical-align: middle; letter-spacing: .3px; }}
            .kw-cve {{ background: #fee2e2; color: #b91c1c; }} .kw-crit {{ background: #fef3c7; color: #a16207; }}
            .source-tag {{ grid-area: source; justify-self: start; display: inline-flex; align-items: center; max-width: 100%; padding: 4px 11px; border-radius: 999px; color: #fff; font-family: 'Poppins','Noto Serif SC',sans-serif; font-size: .76em; font-weight: 700; line-height: 1.2; white-space: nowrap; }}
            .src-doonsec {{ background: #4dabf7; }} .src-chainreactors {{ background: #845ef7; }} .src-brucefeiix {{ background: #20c997; }} .src-mrxn {{ background: #ff922b; }} .src-githubissue {{ background: #495057; }} .src-default {{ background: #adb5bd; }}
            .footer {{ margin-top: 22px; padding: 18px 0 0; color: #8795a7; text-align: center; font-size: .9em; }}
            @media (max-width: 1100px) {{ .dashboard {{ grid-template-columns: 1fr; }} .sidebar {{ position: static; max-height: none; }} .date-nav {{ grid-template-columns: repeat(auto-fit,minmax(150px,1fr)); }} }}
            @media (max-width: 820px) {{ .page-shell {{ width: min(100% - 20px,1480px); padding-top: 12px; }} .hero {{ grid-template-columns: 1fr; padding: 22px; }} .hero-actions {{ align-items: flex-start; }} .stat-grid {{ grid-template-columns: repeat(2,minmax(0,1fr)); }} .search-box {{ top: 8px; flex-wrap: wrap; }} .search-info {{ padding-left: 4px; }} ul {{ grid-template-columns: 1fr; padding: 0 12px 14px; }} }}
            @media (max-width: 520px) {{ .stat-grid {{ grid-template-columns: 1fr; }} h1 {{ font-size: 2.25rem; }} summary {{ padding: 16px; }} li {{ grid-template-columns: 1fr; grid-template-areas: 'idx' 'title' 'source'; }} }}
        </style>
    </head>
    <body>
        <main class="page-shell">
            <section class="hero">
                <div>
                    <div class="eyebrow">Security Intelligence Feed</div>
                    <h1>{page_title}</h1>
                    <p class="hero-subtitle">按时间线聚合最新安全漏洞文章，左侧快速切换日期与来源，右侧以卡片流浏览正文链接。</p>
                    <p class="meta">最后更新时间: {update_time}</p>
                </div>
                <div class="hero-actions"><div class="nav">{nav_link_html}</div></div>
            </section>
            <section class="stat-grid" aria-label="页面统计">{stats_html}</section>
            <section class="dashboard">
                <aside class="sidebar" aria-label="页面导航">
                    <div class="side-section"><h2 class="side-title">日期导航</h2><nav class="date-nav">{date_nav_html}</nav></div>
                    <div class="side-section"><h2 class="side-title">来源分布</h2><div class="source-list">{source_html}</div></div>
                </aside>
                <section class="content-panel">
                    <div class="search-box">
                        <input type="search" id="searchInput" autocomplete="off" spellcheck="false" placeholder="🔍 搜索 CVE、RCE、Weblogic、未授权；支持空格分隔多关键字">
                        <span class="search-info" id="searchInfo"></span>
                    </div>
                    <div class="articles-container">{articles_html}</div>
                    <div class="search-no-result" id="noResult" style="display:none;">没有找到匹配的文章，换个关键字试试 ~</div>
                </section>
            </section>
            <div class="footer"><p>由 GitHub Actions 自动构建</p></div>
        </main>
        {search_script}
    </body>
    </html>
    """

    stats = [
        ('文章总数', total_articles, '当前页面收录文章'),
        ('覆盖天数', total_days, '按 date_added 聚合'),
        ('高危命中', risk_counts.get('高危关键词', 0), '标题包含 RCE/未授权/注入等'),
        ('主要来源', _html.escape(top_source), f'{top_source_count} 篇'),
    ]
    stats_html = "\n".join(
        f'<article class="stat-card"><div class="stat-label">{label}</div>'
        f'<div class="stat-value">{value}</div><div class="stat-note">{note}</div></article>'
        for label, value, note in stats
    )

    date_nav_parts = []
    for date in sorted_dates:
        day_count = len(grouped_articles[date])
        today_class = ' is-today' if date == today_str else ''
        date_nav_parts.append(
            f'<a class="date-link{today_class}" href="#day-{_html.escape(date)}">'
            f'<span>{_html.escape(date)}</span><span class="date-count">{day_count}</span></a>'
        )
    date_nav_html = "\n".join(date_nav_parts) or '<span class="meta">暂无日期</span>'

    source_parts = []
    for source, count in source_counts.most_common():
        dot_cls = source_class(source).replace('src-', 'src-dot-')
        source_parts.append(
            f'<div class="source-row"><span class="name"><span class="source-dot {dot_cls}"></span>'
            f'{_html.escape(source)}</span><span class="count">{count}</span></div>'
        )
    source_html = "\n".join(source_parts) or '<span class="meta">暂无来源</span>'

    articles_html_parts = []
    for i, date in enumerate(sorted_dates):
        open_attribute = ' open' if i == 0 else ''
        summary_class = ' class="today"' if date == today_str else ''
        day_articles = sorted(grouped_articles[date], key=lambda x: x.get('source', ''))

        articles_html_parts.append(f'<details id="day-{_html.escape(date)}"{open_attribute}>')
        articles_html_parts.append(
            f'<summary{summary_class}><h2>{_html.escape(date)}</h2>'
            f'<span class="count-badge">{len(day_articles)} 篇</span></summary>'
        )
        articles_html_parts.append('<ul>')
        for idx, article in enumerate(day_articles, 1):
            link_target = _html.escape(article.get('url', '#'), quote=True)
            title_html = highlight_title(article.get('title', '无标题'))
            source = article.get('source', '未知')
            src_cls = source_class(source)
            articles_html_parts.append(
                f'<li>'
                f'<span class="idx">{idx}</span>'
                f'<span class="article-main"><a href="{link_target}" target="_blank" rel="noopener">{title_html}</a></span>'
                f'<span class="source-tag {src_cls}">{_html.escape(source)}</span>'
                f'</li>'
            )
        articles_html_parts.append('</ul>')
        articles_html_parts.append('</details>')

    articles_html_content = "\n".join(articles_html_parts)
    update_time_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    final_html = html_template.format(
        page_title=page_title,
        update_time=update_time_str,
        nav_link_html=nav_link_html,
        stats_html=stats_html,
        date_nav_html=date_nav_html,
        source_html=source_html,
        articles_html=articles_html_content,
        search_script=SEARCH_SCRIPT
    )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(final_html)
    print(f"[+] 页面 {output_path} 生成成功！")

# --- 主函数 (无变化) ---
def main():
    all_articles_db = read_all_articles_from_archive()
    existing_urls = {article['url'] for article in all_articles_db}

    task = 'today'
    target_date_str = datetime.datetime.now().strftime("%Y-%m-%d")

    if len(sys.argv) > 1:
        arg = sys.argv[1]
        if arg == 'issue':
            task = 'issue'
        else:
            try:
                datetime.datetime.strptime(arg, '%Y-%m-%d')
                target_date_str = arg
                print(f"[*] 已指定目标日期: {target_date_str}")
            except ValueError:
                print(f"[!] 无效的日期格式: {arg}. 请使用 YYYY-MM-DD 格式。将继续获取当天数据。")

    fetched_articles = []
    if task == 'today':
        fetched_articles.extend(get_chainreactors_articles(target_date_str))
        fetched_articles.extend(get_BruceFeIix_articles(target_date_str))
        
        if target_date_str == datetime.datetime.now().strftime("%Y-%m-%d"):
             fetched_articles.extend(get_doonsec_articles())
             fetched_articles.extend(get_mrxn_articles())
    elif task == 'issue':
        fetched_articles.extend(get_issue_articles())
    
    new_articles_to_process = [art for art in fetched_articles if art['url'] not in existing_urls]
    
    if new_articles_to_process:
        print(f"\n--- 发现 {len(new_articles_to_process)} 篇新文章，准备更新列表 ---\n")
        for article in new_articles_to_process:
            article['date_added'] = target_date_str
        save_daily_articles(new_articles_to_process, target_date_str)
        all_articles_db.extend(new_articles_to_process)
    else:
        print("\n--- 没有发现任何新文章 ---")

    if not all_articles_db:
        print("[-] 没有任何文章数据，无法生成页面。")
        return

    cutoff_date = datetime.date.today() - datetime.timedelta(days=RECENT_DAYS)
    recent_articles = [art for art in all_articles_db if art.get('date_added') and datetime.datetime.strptime(art['date_added'], '%Y-%m-%d').date() >= cutoff_date]

    generate_html_page(
        articles=recent_articles,
        output_path='index.html',
        page_title='每日安全漏洞文章聚合 (最近7天)',
        nav_link_html='<a href="archive.html">查看完整归档 &rarr;</a>'
    )

    generate_html_page(
        articles=all_articles_db,
        output_path='archive.html',
        page_title='完整文章归档',
        nav_link_html='<a href="index.html">&larr; 返回首页</a>'
    )

    print(f"\n--- 所有页面处理完毕 ---")

if __name__ == '__main__':
    main()
