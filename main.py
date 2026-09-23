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

# 客户端脚本：搜索条展开/收起 + 来源标签页筛选 + 多关键字实时过滤 + 回到顶部
# 设计语言对齐源站（wechat.doonsec.com 用 jQuery + layui），这里保持零依赖的原生 JS。
PAGE_SCRIPT = """
    <script>
    (function () {
        'use strict';
        var input = document.getElementById('searchInput');
        var info = document.getElementById('searchInfo');
        var noResult = document.getElementById('noResult');
        var bar = document.getElementById('searchBar');
        var toggle = document.getElementById('searchToggle');
        var closeBtn = document.getElementById('searchClose');
        var toTop = document.getElementById('toTop');
        var tabs = Array.prototype.slice.call(document.querySelectorAll('#sourceTabs .tab'));
        var groups = Array.prototype.slice.call(document.querySelectorAll('#articles details.group'));

        // 文章的来源只存一处：badge 上的 src-* 类名（避免与 data-src 重复占体积）
        function srcOf(badge) {
            if (!badge) { return ''; }
            for (var i = 0; i < badge.classList.length; i++) {
                var c = badge.classList[i];
                if (c.indexOf('src-') === 0) { return c.slice(4); }
            }
            return '';
        }

        // 预存每条文章的可搜索文本（标题 + 来源）、所属分组与序号节点，加速匹配
        var items = [];
        groups.forEach(function (g, gi) {
            Array.prototype.forEach.call(g.querySelectorAll('li.entry'), function (li) {
                var a = li.querySelector('a.entry-title');
                var badge = li.querySelector('.badge-src');
                items.push({
                    li: li,
                    gi: gi,
                    seq: li.querySelector('.entry-seq'),
                    src: srcOf(badge),
                    text: ((a ? a.textContent : '') + ' ' + (badge ? badge.textContent : '')).toLowerCase()
                });
            });
        });
        var defaultOpen = groups.map(function (g) { return g.open; });
        var activeSrc = '';

        function debounce(fn, ms) {
            var t;
            return function () { clearTimeout(t); t = setTimeout(fn, ms); };
        }

        function apply() {
            var q = (input.value || '').trim().toLowerCase();
            var keys = q ? q.split(/\\s+/).filter(Boolean) : [];
            var filtering = keys.length > 0 || activeSrc !== '';
            var counts = [];
            var seqs = [];
            var total = 0;
            var i, k;

            for (i = 0; i < groups.length; i++) { counts.push(0); seqs.push(0); }

            for (i = 0; i < items.length; i++) {
                var it = items[i];
                var hit = (activeSrc === '' || it.src === activeSrc);
                if (hit) {
                    for (k = 0; k < keys.length; k++) {
                        if (it.text.indexOf(keys[k]) === -1) { hit = false; break; }
                    }
                }
                it.li.style.display = hit ? '' : 'none';
                if (hit) {
                    counts[it.gi]++;
                    seqs[it.gi]++;
                    if (it.seq) { it.seq.textContent = seqs[it.gi]; }
                    total++;
                }
            }

            for (i = 0; i < groups.length; i++) {
                var c = counts[i];
                groups[i].style.display = c ? '' : 'none';
                var badge = groups[i].querySelector('.badge-count');
                if (badge) { badge.textContent = c; }
                groups[i].open = filtering ? c > 0 : defaultOpen[i];
            }

            info.textContent = filtering ? ('命中 ' + total + ' 篇') : '';
            noResult.style.display = total ? 'none' : 'block';
        }

        // --- 搜索条展开 / 收起（对位源站 .search_main 的交互）---
        function openBar() {
            bar.classList.add('is-open');
            toggle.classList.add('is-active');
            input.focus();
        }
        function closeBar() {
            bar.classList.remove('is-open');
            toggle.classList.remove('is-active');
        }
        toggle.addEventListener('click', function () {
            if (bar.classList.contains('is-open')) { closeBar(); } else { openBar(); }
        });
        closeBtn.addEventListener('click', function () {
            if (input.value) { input.value = ''; apply(); }
            closeBar();
        });

        // --- 来源标签页（对位源站 .layui-tab-title / .tag-li）---
        tabs.forEach(function (t) {
            t.addEventListener('click', function () {
                tabs.forEach(function (x) { x.classList.remove('is-active'); });
                t.classList.add('is-active');
                activeSrc = t.getAttribute('data-src') || '';
                apply();
            });
        });

        input.addEventListener('input', debounce(apply, 120));
        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape' || e.keyCode === 27) {
                if (input.value) { input.value = ''; apply(); } else { closeBar(); }
            } else if (e.key === '/' && document.activeElement !== input) {
                e.preventDefault();
                openBar();
            }
        });

        // --- 回到顶部（对位源站 jquery.toTop.min.js）---
        function onScroll() {
            if (window.pageYOffset > 400) { toTop.classList.add('is-on'); }
            else { toTop.classList.remove('is-on'); }
        }
        window.addEventListener('scroll', onScroll, { passive: true });
        toTop.addEventListener('click', function () {
            window.scrollTo({ top: 0, behavior: 'smooth' });
        });
        onScroll();

        apply();
    })();
    </script>
"""

# 访客统计脚本：本地累计日/周/月/年访问，并同步页脚摘要
VISITOR_SCRIPT = """
    <script>
    (function () {
        var STORE_KEY = 'secalerts_visitor_stats_v1';

        function pad(n) { return n < 10 ? '0' + n : String(n); }
        function dateKey(d) {
            return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate());
        }
        function startOfWeek(d) {
            var x = new Date(d.getFullYear(), d.getMonth(), d.getDate());
            var day = x.getDay();
            var diff = day === 0 ? 6 : day - 1;
            x.setDate(x.getDate() - diff);
            return x;
        }
        function load() {
            try {
                var raw = localStorage.getItem(STORE_KEY);
                if (!raw) return { uid: null, days: {}, visits: 0, last: null };
                var data = JSON.parse(raw) || {};
                if (!data.days || typeof data.days !== 'object') data.days = {};
                return data;
            } catch (e) {
                return { uid: null, days: {}, visits: 0, last: null };
            }
        }
        function save(data) {
            try { localStorage.setItem(STORE_KEY, JSON.stringify(data)); } catch (e) {}
        }
        function recordVisit() {
            var data = load();
            var now = new Date();
            var key = dateKey(now);
            data.days[key] = (data.days[key] || 0) + 1;
            data.visits = (data.visits || 0) + 1;
            data.last = now.toISOString();
            if (!data.uid) {
                data.uid = 'u' + Math.random().toString(36).slice(2, 10) + Date.now().toString(36);
            }
            save(data);
            return data;
        }
        function sumRange(days, fromDate, toDate) {
            var sum = 0;
            var cur = new Date(fromDate.getFullYear(), fromDate.getMonth(), fromDate.getDate());
            var end = dateKey(toDate);
            var guard = 0;
            while (dateKey(cur) <= end && guard < 400) {
                sum += days[dateKey(cur)] || 0;
                cur.setDate(cur.getDate() + 1);
                guard++;
            }
            return sum;
        }
        function setText(id, value) {
            var el = document.getElementById(id);
            if (el) el.textContent = String(value);
        }
        function render(data) {
            var now = new Date();
            var days = data.days || {};
            setText('vs-today', days[dateKey(now)] || 0);
            setText('vs-week', sumRange(days, startOfWeek(now), now));
            setText('vs-month', sumRange(days, new Date(now.getFullYear(), now.getMonth(), 1), now));
            setText('vs-year', sumRange(days, new Date(now.getFullYear(), 0, 1), now));
        }

        render(recordVisit());
    })();
    </script>
"""

# --- 页面样式（自研 CSS，设计语言参考 wechat.doonsec.com；不引入 layui 等第三方框架）---
# 配色 / 尺寸取值来源见 docs/doonsec-design-reference.md 的取证表。
PAGE_CSS = """
/* ==========================================================================
   SecAlerts — 前端样式
   设计语言参考 wechat.doonsec.com：深色顶栏 + 浅灰底 + 白色圆角卡片、
   主色 #009688、layui 式栅格分栏、折叠组 + 标签页、方形小标签（badge / rim）。
   CSS 为自研，零第三方框架依赖。
   ========================================================================== */
:root{
    --bg:#f1f1f1;
    --card:#ffffff;
    --top:#333333;
    --text:#333333;
    --text-2:#666666;
    --muted:#8d8d8d;
    --line:#e9e9e9;
    --line-2:#f0f0f0;
    --primary:#009688;
    --tag:#3962b4;
    --c-doonsec:#1e9fff;
    --c-brucefeiix:#16b777;
    --c-chainreactors:#a233c6;
    --c-mrxn:#ffb800;
    --c-githubissue:#2f363c;
    --c-default:#999999;
    --radius:10px;
    --radius-sm:3px;
    --top-h:56px;
    --wrap:1370px;
}
*{margin:0;padding:0;box-sizing:border-box}
html{scroll-behavior:smooth}
body{
    background:var(--bg);
    color:var(--text);
    font-family:"Microsoft YaHei","微软雅黑",-apple-system,BlinkMacSystemFont,"PingFang SC","Hiragino Sans GB","Helvetica Neue",Arial,sans-serif;
    font-size:14px;
    line-height:1.6;
    -webkit-font-smoothing:antialiased;
}
a{color:inherit;text-decoration:none}
ul,ol{list-style:none}
img{border:0}
button,input{font-family:inherit;font-size:inherit;color:inherit;background:none;border:0;outline:0}
::selection{background:rgba(0,150,136,.18)}

/* ---------- 顶栏：对位源站 .header / .headerinner / .headernav ---------- */
.topbar{position:sticky;top:0;z-index:60;background:var(--top);color:#fff}
.topbar-inner{
    position:relative;
    width:100%;
    max-width:var(--wrap);
    height:var(--top-h);
    margin:0 auto;
    padding:0 16px;
    display:flex;
    align-items:center;
}
.brand{display:flex;align-items:center;gap:9px;margin-right:18px;color:#fff;font-size:19px;font-weight:700;white-space:nowrap}
.brand i{width:9px;height:9px;border-radius:50%;background:var(--primary);box-shadow:0 0 0 4px rgba(0,150,136,.2)}
.nav{display:flex;align-items:center;min-width:0;overflow:hidden}
.nav a{display:flex;align-items:center;height:var(--top-h);padding:0 14px;color:#fff;white-space:nowrap;transition:color .3s}
.nav a:hover{color:var(--primary)}
.nav a.is-active{color:var(--primary)}
.nav-tools{margin-left:auto;display:flex;align-items:center}
.icon-btn{display:flex;align-items:center;justify-content:center;width:44px;height:var(--top-h);color:#fff;cursor:pointer;transition:color .3s}
.icon-btn:hover,.icon-btn.is-active{color:var(--primary)}
.nav-live{display:flex;align-items:center;gap:6px;color:#8d8d8d;font-size:12px;padding-right:4px}
.nav-live i{width:7px;height:7px;border-radius:50%;background:var(--primary);animation:blink 1.6s infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.25}}

/* 搜索条：对位源站 .search_main（点图标展开，覆盖导航条） */
.search-bar{
    position:absolute;
    left:0;right:0;top:0;
    height:var(--top-h);
    padding:0 16px;
    background:var(--top);
    display:none;
    align-items:center;
    gap:10px;
    z-index:2;
}
.search-bar.is-open{display:flex}
#searchInput{
    flex:1 1 auto;
    min-width:0;
    height:38px;
    padding:0 14px;
    border:1px solid #4a4a4a;
    border-radius:var(--radius-sm);
    background:#2b2b2b;
    color:#fff;
    transition:border-color .3s,box-shadow .3s;
}
#searchInput::placeholder{color:#8d8d8d}
#searchInput:focus{border-color:var(--primary);box-shadow:0 0 0 3px rgba(0,150,136,.16)}
.search-info{flex:0 0 auto;color:#5fd6c8;font-size:13px;white-space:nowrap}

/* ---------- 栅格：对位源站 .layui-container + .layui-row + col-md9 / col-md3 ---------- */
.container{width:100%;max-width:var(--wrap);margin:0 auto;padding:16px}
.grid{display:grid;grid-template-columns:minmax(0,1fr) 330px;gap:15px;align-items:start}
.col-main{min-width:0}
.col-side{
    position:sticky;
    top:calc(var(--top-h) + 16px);
    max-height:calc(100vh - var(--top-h) - 32px);
    overflow:auto;
    display:grid;
    gap:15px;
    align-content:start;
    scrollbar-width:thin;
}
.col-side::-webkit-scrollbar{width:6px}
.col-side::-webkit-scrollbar-thumb{background:#d5d5d5;border-radius:3px}

/* ---------- 卡片：对位源站 .layui-card / .article ---------- */
.card{background:var(--card);border-radius:var(--radius);box-shadow:0 2px 5px 0 rgba(0,0,0,.05);overflow:hidden}
.card-head{
    display:flex;
    align-items:center;
    gap:8px;
    padding:11px 16px;
    border-bottom:1px solid var(--line-2);
    font-size:15px;
    font-weight:700;
}
.card-head .badge{margin-left:auto}
.card-body{padding:12px 16px;font-size:13px;color:var(--text-2)}

/* 方形小标签：对位源站 .layui-badge / .layui-badge-rim */
.badge{
    display:inline-block;
    min-width:18px;
    height:18px;
    padding:0 6px;
    border-radius:2px;
    background:#ff5722;
    color:#fff;
    font-size:12px;
    font-style:normal;
    line-height:18px;
    text-align:center;
}
.badge-green{background:var(--primary)}
.badge-blue{background:#1e9fff}
.badge-gray{background:#999}
.badge-src{color:#fff;font-weight:400}
.src-doonsec{background:var(--c-doonsec)}
.src-brucefeiix{background:var(--c-brucefeiix)}
.src-chainreactors{background:var(--c-chainreactors)}
.src-mrxn{background:var(--c-mrxn)}
.src-githubissue{background:var(--c-githubissue)}
.src-default{background:var(--c-default)}
.rim{
    display:inline-block;
    height:20px;
    padding:0 6px;
    border:1px solid var(--line);
    border-radius:2px;
    color:var(--muted);
    font-size:12px;
    line-height:18px;
    vertical-align:middle;
}

/* ---------- 页头（占源站轮播位，放站点标题与更新信息） ---------- */
.page-head{padding:16px 20px 14px}
.page-head h1{margin:0;font-size:22px;font-weight:700;line-height:1.3}
.page-head .digest{margin-top:6px;color:lightslategray;font-size:13px}
.page-head .meta{margin-top:4px;color:var(--muted);font-size:12px}

/* ---------- 来源标签页：对位源站 .layui-tab-title / .tag-li ---------- */
.tabs{
    display:flex;
    overflow-x:auto;
    padding:0 6px;
    border-bottom:1px solid var(--line);
    scrollbar-width:thin;
}
.tabs::-webkit-scrollbar{height:5px}
.tabs::-webkit-scrollbar-thumb{background:#d5d5d5;border-radius:3px}
.tab{
    position:relative;
    flex:0 0 auto;
    display:flex;
    align-items:center;
    gap:6px;
    padding:11px 12px;
    color:var(--text-2);
    white-space:nowrap;
    cursor:pointer;
    transition:color .3s;
}
.tab:hover{color:var(--primary)}
.tab.is-active{color:var(--primary);font-weight:700}
.tab.is-active::after{content:"";position:absolute;left:8px;right:8px;bottom:-1px;height:2px;background:var(--primary)}
.tab .badge{border-radius:2px}

/* ---------- 日期折叠组：对位源站 .layui-colla-item / -title / -content ---------- */
.group{background:var(--card);border-radius:var(--radius);box-shadow:0 2px 5px 0 rgba(0,0,0,.05);margin-bottom:15px;overflow:hidden}
.group>summary{
    display:flex;
    align-items:center;
    gap:10px;
    padding:12px 16px;
    background:#fff;
    cursor:pointer;
    list-style:none;
    transition:background .3s;
}
.group>summary::-webkit-details-marker{display:none}
.group>summary:hover{background:#fafafa}
.group-date{font-size:16px;font-weight:700}
.group.is-today .group-date{color:var(--primary)}
.group>summary .badge-count{margin-left:auto}
.badge-count{cursor:inherit}
.group-arrow{
    width:8px;height:8px;
    border-right:2px solid var(--muted);
    border-bottom:2px solid var(--muted);
    transform:rotate(45deg);
    transition:transform .3s;
}
.group:not([open]) .group-arrow{transform:rotate(-45deg)}
.entries{padding:0 16px 10px}

/* ---------- 文章条目：对位源站 .card 内的 .title / .layui-badge / .layui-badge-rim ---------- */
.entry{display:flex;align-items:flex-start;gap:12px;padding:9px 0;border-top:1px solid var(--line-2)}
.entries>.entry:first-child{border-top:0}
.entry-seq{
    flex:0 0 44px;
    padding-top:3px;
    color:var(--muted);
    font-size:12px;
    text-align:right;
    font-variant-numeric:tabular-nums;
}
.entry-main{flex:1 1 auto;min-width:0;display:flex;align-items:baseline;gap:12px}
.entry-title{flex:1 1 auto;min-width:0;font-size:17px;line-height:1.55;color:var(--text);transition:color .3s}
.entry-title:hover{color:var(--primary)}
.entry-title:visited{color:var(--muted)}
.entry-main .badge-src{flex:0 0 auto}

/* 标题内关键词高亮（复现原有的 CVE / 高危关键词标记） */
.kw{display:inline-block;padding:0 5px;margin:0 1px;border-radius:2px;font-size:.82em;font-weight:700;vertical-align:middle}
.kw-cve{background:#fff2f0;color:#e54d4d}
.kw-crit{background:#fff7e6;color:#d48806}

/* ---------- 侧栏 ---------- */
.side-list{padding:6px}
.date-link{
    display:flex;
    align-items:center;
    gap:8px;
    padding:7px 10px;
    border-radius:var(--radius-sm);
    color:var(--text-2);
    font-size:13px;
    transition:background .3s,color .3s;
}
.date-link:hover{background:var(--bg);color:var(--primary)}
.date-link.is-today{background:rgba(0,150,136,.07);color:var(--primary);font-weight:700}
.date-link .num{margin-left:auto;color:var(--muted);font-size:12px;font-variant-numeric:tabular-nums}
.date-link.is-today .num{color:var(--primary)}
.stat-row{display:flex;align-items:center;gap:10px;padding:6px 0}
.stat-row+.stat-row{border-top:1px solid var(--line-2)}
.stat-row .label{color:var(--text-2)}
.stat-row .badge{margin-left:auto}
.chips{display:flex;flex-wrap:wrap;gap:8px}
.chip{
    display:inline-flex;
    align-items:center;
    gap:6px;
    height:26px;
    padding:0 10px;
    border-radius:2px;
    color:#fff;
    font-size:12px;
    font-weight:700;
}
.chip .n{opacity:.82;font-weight:400}
.stat-line{display:flex;align-items:center;gap:8px;font-size:13px;color:var(--text-2)}
.stat-line+.stat-line{margin-top:6px}
.stat-line .badge{margin-left:auto}
.disclaimer{margin:0;color:#a06000;background:rgba(255,243,205,.6);border-radius:var(--radius-sm);padding:9px 11px;font-size:12px;line-height:1.65}
.page-foot{padding:18px 4px 26px;color:var(--muted);font-size:12px;text-align:center;line-height:1.8}

/* 空结果 / 回到顶部（对位源站 jquery.toTop.min.js） */
.empty{padding:70px 20px;color:var(--muted);text-align:center}
.empty code{background:#fff;border:1px solid var(--line);border-radius:2px;padding:1px 5px;color:var(--text-2)}
.to-top{
    position:fixed;
    right:26px;
    bottom:30px;
    z-index:50;
    display:none;
    align-items:center;
    justify-content:center;
    width:42px;height:42px;
    border-radius:var(--radius-sm);
    background:var(--top);
    color:#fff;
    font-size:18px;
    cursor:pointer;
    transition:background .3s;
}
.to-top.is-on{display:flex}
.to-top:hover{background:var(--primary)}

/* ---------- 响应式（源站为 1300px 桌面固定宽、无适配；此处保留响应式） ---------- */
@media (max-width:1100px){
    .grid{grid-template-columns:minmax(0,1fr)}
    .col-side{position:static;max-height:none;overflow:visible}
}
@media (max-width:720px){
    .container{padding:10px}
    .nav a{padding:0 9px;font-size:13px}
    .nav-live{display:none}
    .search-info{display:none}
    .page-head{padding:14px 14px 12px}
    .page-head h1{font-size:19px}
    .entry{gap:8px}
    .entry-seq{flex:0 0 24px;font-size:11px}
    .entry-title{font-size:15px}
    .entry-main{gap:8px}
    .to-top{right:14px;bottom:16px}
}
"""


# --- HTML主页生成函数 (仪表盘双栏布局) ---
def generate_html_page(articles, output_path, page_title, page_kind='index'):
    """
    生成页面：顶栏 + 概览卡 + 来源标签页 + 按日期折叠的文章列表 + 右侧信息栏。
    布局与设计语言参考 wechat.doonsec.com（源站为 col-md9 内容 + col-md3 侧栏）。
    page_kind: 'index' | 'archive'，决定顶部导航的当前项与互链方向。
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
    # 以数据里最新日期作为“今天”高亮锚点，避免归档停更后首页被日历日滤空
    today_str = sorted_dates[0] if sorted_dates else datetime.datetime.now().strftime("%Y-%m-%d")
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
        <title>{page_title}</title>
        <style>
{page_css}
        </style>
    </head>
    <body>
        <header class="topbar">
            <div class="topbar-inner">
                <a class="brand" href="index.html"><i></i>SecAlerts</a>
                <nav class="nav">
{nav_html}
                </nav>
                <div class="nav-tools">
                    <span class="nav-live"><i></i>每 30 分钟更新</span>
                    <button class="icon-btn" id="searchToggle" type="button" title="搜索（快捷键 /）" aria-label="搜索">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><circle cx="11" cy="11" r="7"></circle><line x1="16.6" y1="16.6" x2="21" y2="21"></line></svg>
                    </button>
                </div>
                <div class="search-bar" id="searchBar">
                    <span class="icon-btn" aria-hidden="true">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><circle cx="11" cy="11" r="7"></circle><line x1="16.6" y1="16.6" x2="21" y2="21"></line></svg>
                    </span>
                    <input type="search" id="searchInput" autocomplete="off" spellcheck="false" placeholder="搜索 CVE、RCE、Weblogic、未授权；支持空格分隔多关键字">
                    <span class="search-info" id="searchInfo"></span>
                    <button class="icon-btn" id="searchClose" type="button" title="关闭（Esc）" aria-label="关闭搜索">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><line x1="6" y1="6" x2="18" y2="18"></line><line x1="18" y1="6" x2="6" y2="18"></line></svg>
                    </button>
                </div>
            </div>
        </header>

        <div class="container">
            <div class="grid">
                <main class="col-main">
                    <section class="card">
                        <div class="page-head">
                            <h1>{page_title}</h1>
                            <p class="digest">{subtitle}</p>
                            <p class="meta">最后更新: {update_time}</p>
                        </div>
                        <nav class="tabs" id="sourceTabs">
{tabs_html}
                        </nav>
                    </section>
                    <section id="articles">
{articles_html}
                    </section>
                    <div class="empty" id="noResult" style="display:none;">没有找到匹配的文章，换个关键字试试 ~</div>
                </main>

                <aside class="col-side">
                    <section class="card">
                        <div class="card-head">数据概览</div>
                        <div class="card-body">
{metrics_html}
                        </div>
                    </section>
                    <section class="card">
                        <div class="card-head">日期导航<span class="badge badge-green">{total_dates}</span></div>
                        <div class="card-body side-list">
{date_nav_html}
                        </div>
                    </section>
                    <section class="card">
                        <div class="card-head">来源分布<span class="badge badge-green">{total_sources}</span></div>
                        <div class="card-body">
                            <div class="chips">
{source_chips_html}
                            </div>
                        </div>
                    </section>
                    <section class="card">
                        <div class="card-head">访问统计</div>
                        <div class="card-body">
                            <p class="stat-line">总访问<span class="badge badge-gray" id="busuanzi_value_site_pv">&hellip;</span></p>
                            <p class="stat-line">独立访客<span class="badge badge-gray" id="busuanzi_value_site_uv">&hellip;</span></p>
                            <p class="stat-line">今日<span class="badge badge-blue" id="vs-today">0</span></p>
                            <p class="stat-line">本周<span class="badge badge-blue" id="vs-week">0</span></p>
                            <p class="stat-line">本月<span class="badge badge-blue" id="vs-month">0</span></p>
                            <p class="stat-line">本年<span class="badge badge-blue" id="vs-year">0</span></p>
                        </div>
                    </section>
                    <section class="card">
                        <div class="card-head">免责声明</div>
                        <div class="card-body">
                            <p class="disclaimer">本站内容均来自互联网公开渠道，仅供安全技术学习参考，不构成任何建议。如有侵权，请联系删除。</p>
                        </div>
                    </section>
                </aside>
            </div>
            <p class="page-foot">由 GitHub Actions 自动构建 &middot; 数据来自 ChainReactors / BruceFeIix / Doonsec / MRXN</p>
        </div>

        <div class="to-top" id="toTop" title="回到顶部">&uarr;</div>
{page_script}
{visitor_script}
{analytics_script}
    </body>
    </html>
    """

    # ---- 顶部导航（对位源站 .headernav）----
    nav_defs = [
        ('index.html', '首页', 'index'),
        ('archive.html', '归档', 'archive'),
        ('https://wechat.doonsec.com/rss.xml', 'RSS', None),
        ('https://github.com/wy876/SecAlerts', 'GitHub', None),
    ]
    nav_parts = []
    for href, label, kind in nav_defs:
        cls = ' class="is-active"' if kind == page_kind else ''
        target = ' target="_blank" rel="noopener"' if href.startswith('http') else ''
        nav_parts.append(f'<a href="{href}"{cls}{target}>{label}</a>')
    nav_html = "\n".join(nav_parts)

    subtitle = (
        '按时间线聚合最新安全漏洞文章；点击日期展开文章列表，右上角可搜索，也可按来源筛选。'
        if page_kind == 'index' else
        '全部历史文章的完整归档，按日期倒序排列；可通过右侧日期导航快速跳转，或按来源筛选。'
    )

    # ---- 数据概览（对位源站的侧栏统计卡）----
    metrics = [
        ('文章总数', total_articles, 'badge-green'),
        ('覆盖天数', total_days, 'badge-green'),
        ('漏洞编号命中', risk_counts.get('漏洞编号', 0), 'badge-gray'),
        ('高危关键词命中', risk_counts.get('高危关键词', 0), ''),
        ('主要来源', _html.escape(top_source), 'badge-blue'),
    ]
    metrics_html = "\n".join(
        f'                            <div class="stat-row"><span class="label">{label}</span>'
        f'<span class="badge {cls}">{value}</span></div>'
        for label, value, cls in metrics
    )

    # ---- 来源标签页（对位源站 .layui-tab-title / .tag-li）----
    tab_parts = [
        f'                            <button class="tab is-active" type="button" data-src="">'
        f'全部<span class="badge badge-green">{total_articles}</span></button>'
    ]
    for source, count in source_counts.most_common():
        key = re.sub(r'[^a-z0-9]', '', (source or '').lower())
        tab_parts.append(
            f'                            <button class="tab" type="button" data-src="{_html.escape(key, quote=True)}">'
            f'{_html.escape(source)}<span class="badge badge-green">{count}</span></button>'
        )
    tabs_html = "\n".join(tab_parts)

    # ---- 日期导航（对位源站侧栏列表卡）----
    date_nav_parts = []
    for date in sorted_dates:
        day_count = len(grouped_articles[date])
        today_class = ' is-today' if date == today_str else ''
        date_nav_parts.append(
            f'                            <a class="date-link{today_class}" href="#day-{_html.escape(date)}">'
            f'<span>{_html.escape(date)}</span><span class="num">{day_count}</span></a>'
        )
    date_nav_html = "\n".join(date_nav_parts) or '                            <span class="meta">暂无日期</span>'

    # ---- 来源分布（彩色 chip，对位源站右栏公众号目录的彩色标签）----
    source_chips = []
    for source, count in source_counts.most_common():
        src_cls = source_class(source)
        source_chips.append(
            f'                                <span class="chip {src_cls}">{_html.escape(source)}'
            f'<span class="n">{count}</span></span>'
        )
    source_chips_html = "\n".join(source_chips) or '                                <span class="meta">暂无来源</span>'

    # ---- 文章区：按日期折叠组（对位源站 .layui-colla-item）----
    articles_html_parts = []
    for i, date in enumerate(sorted_dates):
        open_attribute = ' open' if i == 0 else ''
        group_cls = 'group is-today' if date == today_str else 'group'
        day_articles = sorted(grouped_articles[date], key=lambda x: x.get('source', ''))

        articles_html_parts.append(
            f'                        <details class="{group_cls}" id="day-{_html.escape(date)}"{open_attribute}>'
        )
        articles_html_parts.append(
            f'                            <summary><span class="group-arrow"></span>'
            f'<span class="group-date">{_html.escape(date)}</span>'
            f'<span class="badge badge-green badge-count">{len(day_articles)}</span></summary>'
        )
        articles_html_parts.append('                            <ul class="entries">')
        for idx, article in enumerate(day_articles, 1):
            link_target = _html.escape(article.get('url', '#'), quote=True)
            title_html = highlight_title(article.get('title', '无标题'))
            source = article.get('source', '未知')
            src_cls = source_class(source)
            articles_html_parts.append(
                f'                                <li class="entry">'
                f'<span class="entry-seq">{idx}</span>'
                f'<span class="entry-main">'
                f'<a class="entry-title" href="{link_target}" target="_blank" rel="noopener">{title_html}</a>'
                f'<span class="badge badge-src {src_cls}">{_html.escape(source)}</span>'
                f'</span></li>'
            )
        articles_html_parts.append('                            </ul>')
        articles_html_parts.append('                        </details>')

    articles_html_content = "\n".join(articles_html_parts)
    update_time_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    analytics_script = '<script async src="https://busuanzi.ibruce.info/busuanzi/2.3/busuanzi.pure.mini.js"></script>\n'
    final_html = html_template.format(
        page_title=page_title,
        subtitle=subtitle,
        page_css=PAGE_CSS,
        nav_html=nav_html,
        tabs_html=tabs_html,
        metrics_html=metrics_html,
        date_nav_html=date_nav_html,
        source_chips_html=source_chips_html,
        articles_html=articles_html_content,
        total_articles=total_articles,
        total_dates=total_days,
        total_sources=len(source_counts),
        update_time=update_time_str,
        page_script=PAGE_SCRIPT,
        visitor_script=VISITOR_SCRIPT,
        analytics_script=analytics_script,
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
        if arg == 'build':
            # 仅根据 archive 重建 HTML，不拉取新文章；近 N 天以归档最新日期为锚点
            print("[*] build 模式：跳过抓取，直接生成页面。")
            dated = [art for art in all_articles_db if art.get('date_added')]
            if dated:
                latest_date = max(datetime.datetime.strptime(a['date_added'], '%Y-%m-%d').date() for a in dated)
            else:
                latest_date = datetime.date.today()
            cutoff_date = latest_date - datetime.timedelta(days=RECENT_DAYS)
            recent_articles = [
                art for art in dated
                if datetime.datetime.strptime(art['date_added'], '%Y-%m-%d').date() >= cutoff_date
            ]
            generate_html_page(
                articles=recent_articles,
                output_path='index.html',
                page_title='每日安全漏洞文章聚合 (最近7天)',
                page_kind='index'
            )
            generate_html_page(
                articles=all_articles_db,
                output_path='archive.html',
                page_title='完整文章归档',
                page_kind='archive'
            )
            print("\n--- 页面重建完毕 ---")
            return
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

    dated = [art for art in all_articles_db if art.get('date_added')]
    if dated:
        latest_date = max(datetime.datetime.strptime(a['date_added'], '%Y-%m-%d').date() for a in dated)
    else:
        latest_date = datetime.date.today()
    cutoff_date = latest_date - datetime.timedelta(days=RECENT_DAYS)
    recent_articles = [
        art for art in dated
        if datetime.datetime.strptime(art['date_added'], '%Y-%m-%d').date() >= cutoff_date
    ]

    generate_html_page(
        articles=recent_articles,
        output_path='index.html',
        page_title='每日安全漏洞文章聚合 (最近7天)',
        page_kind='index'
    )

    generate_html_page(
        articles=all_articles_db,
        output_path='archive.html',
        page_title='完整文章归档',
        page_kind='archive'
    )

    print(f"\n--- 所有页面处理完毕 ---")

if __name__ == '__main__':
    main()
