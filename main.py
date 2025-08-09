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
from collections import defaultdict

# --- 全局配置 ---
ARCHIVE_DIR = 'archive'
RECENT_DAYS = 7 # 首页显示最近N天的文章

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
    keyword_pattern = r'(复现|漏洞|CVE-\d+|CNVD-\d+|CNNVD-\d+|XVE-\d+|QVD-\d+|POC|EXP|0day|1day|nday|RCE|代码执行|命令执行|代码审计)'
    link_pattern = r'\[(.*?)\]\((https://mp\.weixin\.qq\.com/.*?)\)'
    for line in content.splitlines():
        if re.search(keyword_pattern, line, re.I):
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
    keyword_pattern = r'(复现|漏洞|CVE-\d+|CNVD-\d+|CNNVD-\d+|XVE-\d+|QVD-\d+|POC|EXP|0day|1day|nday|RCE|代码执行|命令执行|代码审计|渗透)'
    try:
        response.encoding = response.apparent_encoding
        root = ET.fromstring(response.text)
        for item in root.findall('./channel/item'):
            title, link = (item.findtext('title') or '').strip(), (item.findtext('link') or '').strip()
            if re.search(keyword_pattern, title, re.I) and link.startswith('https://mp.weixin.qq.com/'):
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
    # 如果需要过滤，可以取消下面这行注释
    # keyword_pattern = r'(复现|漏洞|CVE-\d+|CNVD-\d+|POC|EXP|RCE|代码执行|命令执行|代码审计|渗透)'
    try:
        response.encoding = response.apparent_encoding
        root = ET.fromstring(response.text)
        for item in root.findall('./channel/item'):
            title = (item.findtext('title') or '').strip()
            link = (item.findtext('link') or '').strip()

            # MRXN 的链接多样，不需要过滤微信链接，只要标题和链接存在即可
            if title and link:
                # if re.search(keyword_pattern, title, re.I): # 如果需要过滤，取消此行注释
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

# --- HTML主页生成函数 (★★★ 已修改CSS为紧凑布局 ★★★) ---
def generate_html_page(articles, output_path, page_title, nav_link_html):
    """
    生成一个按日期分组的、可折叠的聚合页面。
    """
    print(f"[*] 正在生成页面: {output_path}...")
    
    grouped_articles = defaultdict(list)
    for article in articles:
        date = article.get('date_added', '未知日期')
        grouped_articles[date].append(article)
        
    sorted_dates = sorted(grouped_articles.keys(), reverse=True)
    today_str = datetime.datetime.now().strftime("%Y-%m-%d")
    
    # 修正：将所有 CSS 的 { 和 } 替换为 {{ 和 }} 以避免 format 错误
    # 修正：将 h1 和 summary 的字体大小改回 em 单位，以保证正确的视觉层级
    html_template = """
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>安全文章聚合</title>
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=Noto+Serif+SC:wght@400;700&family=Poppins:wght@700&display=swap" rel="stylesheet">
        <style>
            /* --- 全局与基础样式 --- */
            body {{
                font-family: 'Noto Serif SC', serif;
                font-size: 15px; /* 基础字体大小 */
                line-height: 1.8;
                margin: 0;
                padding: 30px 15px;
                background-color: #f4f7f9;
                color: #333;
                transition: background-color 0.3s;
            }}

            .container {{
                max-width: 850px;
                margin: auto;
                background: #ffffff;
                padding: 30px 50px;
                box-shadow: 0 8px 30px rgba(0, 0, 0, 0.08);
                border-radius: 12px;
            }}

            /* --- 标题与元信息 --- */
            h1 {{
                font-family: 'Poppins', 'Noto Serif SC', sans-serif;
                font-size: 2.0em; /* ★★★ 修正：使用 em 单位保持相对大小 */
                font-weight: 700;
                text-align: center;
                margin-bottom: 10px;
                background: linear-gradient(45deg, #007BFF, #0056b3);
                -webkit-background-clip: text;
                background-clip: text;
                -webkit-text-fill-color: transparent;
            }}
            
            .meta {{
                font-size: 0.9em;
                color: #888;
            }}

            p.meta {{
                text-align: center;
                margin-bottom: 30px;
            }}
            
            /* --- 导航按钮 --- */
            .nav {{
                text-align: center;
                margin: 25px 0;
                border-top: 1px solid #e9ecef;
                border-bottom: 1px solid #e9ecef;
                padding: 15px 0;
            }}
            .nav a {{
                display: inline-block;
                margin: 0 10px;
                padding: 8px 18px;
                border-radius: 20px;
                background-color: #e9ecef;
                color: #495057;
                text-decoration: none;
                font-weight: bold;
                transition: all 0.3s ease;
            }}
            .nav a:hover, .nav a.current {{
                background-color: #007bff;
                color: #fff;
                box-shadow: 0 4px 10px rgba(0, 123, 255, 0.3);
                transform: translateY(-2px);
            }}

            /* --- 可折叠的文章分组 (卡片式) --- */
            details {{
                border: none;
                border-radius: 10px;
                margin-bottom: 18px;
                overflow: hidden;
                background: #fff;
                box-shadow: 0 4px 12px rgba(0,0,0,0.05);
                transition: box-shadow 0.3s ease;
            }}
            details:hover {{
                box-shadow: 0 6px 16px rgba(0,0,0,0.08);
            }}
            details[open] {{
                box-shadow: 0 6px 20px rgba(0,0,0,0.1);
            }}
            
            summary {{
                padding: 15px 25px;
                background-color: #f8f9fa;
                cursor: pointer;
                outline: none;
                font-size: 1.05em; /* ★★★ 修正：使用 em 单位保持相对大小 */
                font-weight: bold;
                color: #343a40;
                display: flex;
                align-items: center;
                transition: background-color 0.3s ease;
            }}
            summary:hover {{
                background-color: #e9ecef;
            }}
            summary::-webkit-details-marker {{
                display: none;
            }}
            summary::before {{
                content: '►';
                margin-right: 12px;
                font-size: 0.8em;
                color: #007bff;
                transition: transform 0.3s ease;
            }}
            details[open] > summary::before {{
                transform: rotate(90deg);
            }}
            
            .today h2 {{
                color: #007bff;
            }}
            details[open] > summary {{
                border-bottom: 1px solid #dee2e6;
            }}

            /* --- 文章列表 --- */
            ul {{
                list-style-type: none;
                padding: 15px 25px 20px 25px;
                margin: 0;
                background: #fff;
            }}

            li {{
                padding: 12px 15px;
                margin-bottom: 8px;
                border-left: 4px solid #007bff;
                background-color: #fdfdff;
                border-radius: 6px;
                transition: transform 0.2s ease, box-shadow 0.2s ease, background-color 0.2s ease;
            }}
            li:hover {{
                transform: translateX(5px);
                box-shadow: 0 4px 10px rgba(0, 0, 0, 0.06);
                background-color: #f8f9fa;
            }}

            li a {{
                text-decoration: none;
                color: #0056b3;
                font-weight: bold;
                font-size: 1em; /* 字体大小与正文一致 */
            }}
            li a:hover {{
                text-decoration: underline;
            }}
            
            li .meta {{
                margin-top: 5px;
                display: block;
            }}

            /* --- 页脚 --- */
            .footer {{
                text-align: center;
                margin-top: 50px;
                padding-top: 20px;
                border-top: 1px solid #e9ecef;
                font-size: 0.9em;
                color: #aaa;
            }}

        </style>
    </head>
    <body>
        <div class="container">
            <h1>{page_title}</h1>
            <p class="meta">最后更新时间: {update_time}</p>
            
            <div class="nav">{nav_link_html}</div>

            <div class="articles-container">
                {articles_html}
            </div>

            <div class="footer">
                <p>由 GitHub Actions 自动构建</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    articles_html_parts = []
    for i, date in enumerate(sorted_dates):
        open_attribute = ' open' if i == 0 else ''
        summary_class = ' class="today"' if date == today_str else ''
        
        articles_html_parts.append(f'<details{open_attribute}>')
        articles_html_parts.append(f'<summary{summary_class}><h2>{date}</h2></summary>')
        
        articles_html_parts.append('<ul>')
        day_articles = sorted(grouped_articles[date], key=lambda x: x.get('source', ''))
        for article in day_articles:
            link_target = article.get('url', '#')
            articles_html_parts.append(f"""
            <li><a href="{link_target}" target="_blank">{article.get('title', '无标题')}</a><div class="meta">来源: {article.get('source', '未知')}</div></li>
            """)
        articles_html_parts.append('</ul>')
        articles_html_parts.append('</details>')

    articles_html_content = "\n".join(articles_html_parts)
    update_time_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    final_html = html_template.format(page_title=page_title, update_time=update_time_str, nav_link_html=nav_link_html, articles_html=articles_html_content)
    
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
        page_title='每日安全文章聚合 (最近7天)',
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