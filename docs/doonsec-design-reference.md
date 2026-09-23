# doonsec 前端设计参考（取证记录）

本文档记录 SecAlerts 前端改版所依据的**源站取证事实**。改版目标：把 SecAlerts 的页面
改造成 `https://wechat.doonsec.com/` 的设计语言；CSS 全部自研，不引入源站的 layui 或图片资源。

- 取证时间：2026-09-23（UTC 02:36–02:45）
- 目标 URL：`https://wechat.doonsec.com/`
- 探测方式：`website-rebuild` 技能的 Step 0 指纹协议（`scripts/fingerprint.mjs`）+ 定向抓取
- 抓取物 sha256（仅登记，未入库——抓取物是他人的页面内容，不随本仓库分发）：
  - `a.html` 2,294,406 B · `67427cc83420d2f2a348733a7bdc3c30c58ca87a9929859d75928c5553e9f728`
  - `b.html` 2,294,406 B · `6b0949a3b6195cf7e8b72145cae4d20d474f37b502d3d5da8a2194973b969ca0`

## 1. 判级结论：D 类（服务端 CMS 内容站）

| 判据 | 事实 |
|---|---|
| 服务端渲染 | GET 200，无重定向，单页 HTML 2.29 MB，文章内容全部内联在服务端响应里 |
| 后端指纹 | `Server: nginx`、`Vary: Cookie`、Flask 风格签名 `session` cookie、`meta[name=csrf-token]` |
| 前端栈 | jQuery + layui（`/static/front/layui/`）+ 自研公共库 `zlajax.js` / `zlparam.js` / `token.js` / `md5.js` |
| 框架标记 | Next RSC `self.__next_f` = 0、`__NUXT__` = 0、Vue scoped `data-v-` = 0、React Router = 0 |
| 行为位置 | 搜索、文章列表、配图（`/get_img/`）、账号目录全在服务端；客户端只有悬停二维码卡、折叠组、标签页等渐进增强 |
| `robots.txt` | **无有效爬取禁令**：全文仅 `User-agent: *` 与一行被注释掉的 `# Disallow: /`。逐路径判定（选组 → 最长匹配 → 无匹配即允许）→ 允许 |

**结论**：源站客户端没有可移植的签名行为，确定性验收也无基准，因此**不做 1:1 工程化复刻
（L2/L3）**。本次改版按「借鉴其布局与设计语言、CSS 自研」执行，判级结论即为此决策的依据。

## 2. 设计 token（数值全部逆向自源站 CSS）

来源文件：`/static/front/css/front_base.css`（5,496 B）+ `/static/front/css/front_new_index.css`（1,985 B），
两者均**未压缩、手写**。

| 项 | 源站取值 | 本页取值 | 说明 |
|---|---|---|---|
| 字体 | `"微软雅黑"` | `"Microsoft YaHei","微软雅黑",…` 系统字体栈 | 本页移除了原先的 Google Fonts 外链 |
| 页面底色 | `#f1f1f1` | 同 | |
| 顶栏 | `#333333`，高 `50px`，字号 `14px` | 同（高 56px） | 高度略增以容纳搜索按钮 |
| 导航项 | `li{margin:0 20px}` `a{padding:0 10px}` 白字 | `a{padding:0 14px}` 白字 | |
| 主色 / hover | `#009688` | 同 | 导航 hover、链接 hover、激活态、下划线 |
| 正文链接 | `#333` → hover `#009688` → visited `#8D8D8D` | 同 | |
| 弱化文字 | `#8D8D8D`、`lightslategray` | 同 | 序号、摘要、页码 |
| 分类标签色 | `#3962b4`（`.tag_list`） | 保留为 `--tag` | |
| 卡片 | 白底 + 极淡投影 | 白底 + `0 2px 5px rgba(0,0,0,.05)` | layui-card 默认投影 |
| 圆角 | `.article` 10px、部分内联 15px | 统一 `10px` | |
| 小标签 | `.layui-badge` 高 18px / `padding 0 6px` / `border-radius 2px` / 字号 12px | 同（`.badge`） | **方形**小标签，非胶囊——这是源站的显著特征 |
| 描边标签 | `.layui-badge-rim` | `.rim`（保留，当前未使用） | 源站用它承载文章的公众号/地区/点赞/阅读/时间 |
| 容器宽 | `.layui-container` 1370px；`body min-width:1300px` | 1370px，**响应式** | 源站无移动端适配 |
| 栅格 | `col-md9`（内容）+ `col-md3`（侧栏），`layui-col-space15` | CSS Grid `minmax(0,1fr) / 330px`，gap `15px` | |

## 3. 布局映射（源站 → 本页）

源站首页结构（逆向自响应 HTML 骨架）：

```
.header            顶部深色导航条（logo + 导航 + 搜索图标）
.layui-container
└ .layui-row
  ├ .layui-col-md9                 ← 内容列
  │ ├ #test1 .layui-carousel       轮播图（4 张）
  │ ├ .layui-tab-title             35 个 .tag-li 分类标签页
  │ └ #demo .article               文章列表容器（服务端留空，由 front_new_search.js ajax 填充）
  └ .layui-col-md3                 ← 侧栏
    ├ .deleted-monitor-card        删文动态（红点闪烁 + 滚动 feed）
    └ #right                       公众号目录卡（.layui-collapse 16 个折叠组，组内彩色 chip）
```

映射到本页：

| 源站 | 本页 | 备注 |
|---|---|---|
| `.headernav` 导航 | `.topbar` / `.nav` | 首页 / 归档 / RSS / GitHub |
| `.search_main`（点图标展开的搜索条） | `.search-bar` | 交互一致：点图标展开覆盖导航条，含关闭按钮 |
| `.layui-carousel` | `.page-head` | **未做轮播**——本页无图片内容，不发明素材 |
| `.layui-tab-title` / `.tag-li` | `#sourceTabs` / `.tab` | 按**来源**分类（全部 / Doonsec / BruceFeIix / ChainReactors / MRXN） |
| `.layui-colla-item` 折叠组 | `details.group` | 按**日期**折叠；最新一天默认展开 |
| 源站文章条目：`[封面图 col-md2]` + `[标题 / 摘要 / 标签行 / 元信息 rim 行 col-md10]` | `.entry`：`[序号 44px]` + `[标题 17px · 来源 badge]` | 本页无封面图与摘要，故不设对应槽位 |
| 右栏公众号目录的彩色 chip | `.chip` 来源分布 | 每个来源一个固定色 |
| `.deleted-monitor-card` | **未做** | 本页无对应数据 |
| `jquery.toTop.min.js` | `.to-top` | 原生 JS 实现 |

## 4. 有意偏差登记

按纪律，「没登记的差异一律视为 bug」，故逐条登记：

| # | 源站怎么做 | 本页怎么做 | 为什么 | 何时重新考虑 |
|---|---|---|---|---|
| 1 | 标题字号 19px（`.title`） | 17px | 归档页一次性渲染 15,109 条，19px 会显著拉长页面 | 若改为分页/懒加载 |
| 2 | `body min-width:1300px`，无移动端适配 | 保留响应式（≤1100px 单列，≤720px 紧凑） | 用户明确要求保留响应式 | — |
| 3 | 文章条目在标题下渲染 CVE / 关键词的 rim 标签行 | 把这些关键词**内联高亮**在标题里（复现 SecAlerts 原有行为） | 同一信息不重复渲染两遍 | 若需要按 CVE 做结构化筛选 |
| 4 | 使用 layui 框架（CSS/JS/图标字体） | 零第三方框架，自研 CSS + 原生 JS | 用户选择「借鉴布局，视觉自研」；避免第三方框架授权与资源再分发 | — |
| 5 | 顶栏 `transition: 0.6s` | `0.3s` | 0.6s 的配色过渡观感迟滞 | — |
| 6 | 顶栏 `position` 为普通流（侧栏用 `position:fixed`） | 顶栏 `sticky`，侧栏 `sticky` | 现代等价，且不破坏响应式 | — |
| 7 | 文章间用 `<hr>` 分隔 | `li + li { border-top }` | 渲染结果相同，DOM 更干净 | — |
| 8 | 每请求随机生成 chip 颜色（`background-color:#xxxxxx`） | 来源颜色固定（写进 CSS 变量） | 随机会让同一来源每次刷新变色，且无法用于筛选 | — |
| 9 | Google Fonts `Noto Serif SC` + `Poppins`（本仓库改版前） | 移除，改用 `微软雅黑` 系统字体栈 | 与源站一致；同时消除一条外链依赖、国内加载更稳 | — |
| 10 | 卡片圆角混合 10px / 15px | 统一 10px | 一致性 | — |

## 5. 保留的既有功能（未被改版削弱）

页面标题与副标题、数据概览（文章总数 / 覆盖天数 / 漏洞编号命中 / 高危关键词命中 / 主要来源）、
日期导航（含篇数与最新日期高亮）、来源分布统计、多关键字实时搜索（空格分隔 AND、命中计数、
Esc 清空、无结果提示）、标题内关键词高亮（`.kw-cve` / `.kw-crit`）、按日期折叠分组、
访客统计（busuanzi 总访问/独立访客 + localStorage 今日/本周/本月/本年）、免责声明、
首页 ↔ 归档互链、GitHub Actions 自动构建。

新增：回到顶部按钮（对齐源站的 `jquery.toTop`）、来源标签页筛选、搜索条展开交互与 `/` 快捷键。

## 6. 验证记录

用无头 Chrome（CDP 探针）实测，环境：Chrome 桌面版、视口 1440×1200 / 1440×1100。

| 断言 | index.html | archive.html |
|---|---|---|
| 控制台消息 | 0 | 0 |
| 页面错误 | 1 —— 仅浏览器默认请求 `/favicon.ico` 得 404 | 同 |
| 请求失败 | 1（同上 favicon） | 1（favicon）；某次运行还出现外链 busuanzi 脚本超时 |
| 折叠组数 | 8 | 327 |
| 文章条目数 | 301 | 15,109 |
| 默认展开组 | 1（最新日期） | 1（最新日期） |
| 来源标签页 | 4 | 5 |
| 日期导航项 | 8 | 327 |
| 计算样式抽查 | `--primary:#009688`、body `rgb(241,241,241)`、顶栏 `rgb(51,51,51)`、标题 17px、主栏 993px + 侧栏 330px；条目分隔线 1px `rgb(240,240,240)` 全宽 961px，首条无上边框，序号无下划线 | 同 |
| 来源 badge 取色 | 主来源 Doonsec = `rgb(30,159,255)` = `#1e9fff` | 同 |
| 交互实测 | 点「BruceFeIix」→ 54 条可见 / 7 组全展开 / 序号重排为 1…54；搜索「CVE 复现」→ 命中 10 篇、搜索条展开且输入框聚焦 | 点「MRXN」→ 切换耗时 17ms；切回「全部」→ 30ms；搜索「CVE」→ 命中 2,442 / 15,109 条 |

过滤逻辑为单遍线性扫描 + 组内序号重排，归档页 15,109 条的全量筛选实测 **17–30 ms**，
无性能问题。唯一的非本页可控失败来自外链统计脚本 busuanzi。

渲染快照（终稿重拍，与上表同一次运行）：`docs/compare/rebuild-index.jpg`（335,739 B，
sha256 前缀 `e92dda04ed7b7e27`）、`docs/compare/rebuild-archive.jpg`（281,035 B，
sha256 前缀 `f5f3418629254b7c`）。

⚠️ 上表与快照是 **2026-09-23 上午那一次数据快照**的冻结记录（327 组 / 15,109 条）。archive
目录由 CI 每 30 分钟追加，因此线上页面的组数与条目数会持续增长（同日晚间重建已为 412 组 /
17,359 条）；比例、布局与性能特征不受影响。截图不再与线上逐像素一致，属预期。

已知遗留（改版前即存在，本次未处理）：页面仍依赖外链 `https://busuanzi.ibruce.info/...`
统计脚本；无 `favicon.ico`。

## 7. 版权与部署边界

源站为第三方站点。本次改版**只借鉴其布局与设计语言，不复制其 CSS、JS、图片、字体或框架资源**；
从源站抓取的 HTML/JS/CSS 副本已从工作目录删除，未随本仓库分发。

⚠️ SecAlerts 目前公开部署于 GitHub Pages（`https://wy876.github.io/SecAlerts/`）。
「风格借鉴」本身不构成复制，但**是否公开部署、是否需要标注设计灵感来源，由项目所有者决定**。
