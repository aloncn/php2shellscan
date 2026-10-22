# php2shellscan

PHP2Shell(CVE-2026-109618 / CVE-2026-109619)暴露面评估扫描器。纯 Python 标准库实现,无第三方依赖。

> ⚠️ 仅用于对**你拥有或已获授权**的系统进行安全评估。

## 背景

2026-10-21 PHP 官方发布安全更新,修复 Wiz Research 披露的两个核心引擎漏洞(合称 **PHP2Shell**,CVSS 9.2):

| CVE | 缺陷 | 可达成的效果 |
|---|---|---|
| CVE-2026-109618 | OOM 处理导致的内存破坏:session upload-progress 反序列化 UAF;RFC1867 解析阶段 `PS(id)` 悬挂指针 | 跨请求内存破坏 → 前置 RCE;无认证 worker 内存泄露(通过 `PHPSESSID` cookie 回显) |
| CVE-2026-109619 | OOM 处理导致的内存破坏:fatal-error backtrace UAF;OPcache 跨 worker 类型混淆 | 前置 RCE;共享 OPcache 状态破坏 → RCE |

- 影响近十年所有 PHP 版本(≥ 5.4)至少其一。
- 漏洞位于 PHP 引擎层,与上层应用无关("Hello World" 一样中招)。
- **修复版本:8.2.35 / 8.3.36 / 8.4.27 / 8.5.12**;7.4–8.1 仅有最小源码补丁,≤7.3 无官方修复。

参考资料:
- Wiz Research: <https://www.wiz.io/blog/php2shell-php-rce>
- PHP 官方通告(GHSA): <https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w>, <https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp>
- NCSC-NL 公告: <https://vulnerability.circl.lu/vuln/NCSC-2026-0443>

## 设计原则:检测而非利用

真实利用需要诱导 worker 发生 OOM 中止,会使生产 worker 崩溃并污染内存——扫描器**不做**这件事。它组合多类信息得出判定:

1. **版本指纹(分层信息源,应对 `expose_php=Off`)**:
   - `X-Powered-By` / `Server` 响应头(最直接,但常被隐藏);
   - PHP credits 页 `/?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000`(`expose_php=On` 时返回,正文含版本);
   - 遗留 phpinfo 页面 `/phpinfo.php`、`/info.php`、`/test.php`、`/php.php`(正文 `PHP Version x.y.z`);
   - 暴露的 `composer.json` / `composer.lock`(`require.php` 平台约束,注意这是**下界**而非运行版本);
   - `/index.php` 上的头重试(部分代理只剥根路由的缓存头)。
2. **安全主动探测**(可用 `--passive` 关闭):
   - 携带 `PHP_SESSION_UPLOAD_PROGRESS` 的**微小** multipart 请求(数十字节,不触发任何大分配),
     检测 session 模块是否会在 multipart 预初始化路径上生效——这是 CVE-2026-109618
     upload-progress RCE 链的前置条件;
   - 记录基线 `PHPSESSID` 长度,超长(>128 字符)即标记为疑似内存泄露原语信号
     (泄露路径会把释放堆内存 URL-encode 进 session cookie)。
3. **版本隐藏策略**:服务器隐藏头且所有泄露源都拿不到版本时,默认判 `unknown`;
   `--assume-vulnerable` 按保守风险策略改判 `assumed_vulnerable`(critical, unconfirmed)
   ——因为公告前的所有 ≥5.4 构建都至少中一个漏洞,除非证明已打补丁。
4. **SAPI 提示**与聚合判定,输出修复与缓解建议。

## 使用

```bash
cd php2shellscan

# 单目标
python3 -m php2shellscan https://example.com

# 多目标 / 文件 / 并发 / 超时
python3 -m php2shellscan -f targets.txt -c 16 -t 5

# 仅被动指纹(不发任何主动请求)
python3 -m php2shellscan https://example.com --passive

# JSON 报告
python3 -m php2shellscan https://example.com -o report.json --json-only
```

输出示例(本机 PHP 8.1.0 靶场实测):

```
TARGET                 PHP    VERDICT     SEVERITY  CVES            NOTES
--------------------------------------------------------------------------------------------------------------------------------
http://127.0.0.1:8099  8.1.0  vulnerable  critical  109618, 109619  PHP 8.1.0 is EOL and affected by at least one of CVE-2026-10
```

JSON 报告包含每个目标的原始指纹(`raw`)与结构化判定(`verdicts`:版本、CVE、攻击面前置条件、建议),便于接入资产管理系统。

## 判定口径

| 情形 | 判定 |
|---|---|
| 8.2.x < 8.2.35 / 8.3.x < 8.3.36 / 8.4.x < 8.4.27 / 8.5.x < 8.5.12 | **vulnerable**(critical) |
| ≤ 8.1(≥ 5.4,公告前所有旧分支) | **vulnerable** — eol_unpatched,仅最小补丁或无补丁 |
| ≥ 所在分支修复版本 | patched |
| 版本隐藏且无泄露源 | unknown;`--assume-vulnerable` 时改判 assumed_vulnerable |
| 无法确认是 PHP | unknown(需人工核查) |

注意:版本判定是"受影响版本范围内"的判定;是否可达 RCE 还取决于 worker 复用、OPcache、WAF 等运行时条件,探测信号部分已尽力标注这些前置条件。

## 缓解建议(判定为 vulnerable 时输出)

- 唯一彻底修复:升级到 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12(7.4–8.1 应用最小源码补丁);
- 降低 FPM `pm.max_requests` 加速 worker 回收,限制跨请求状态复用窗口;
- `memory_limit` 保持收紧,监控 memory-limit fatal;
- 启用 WAF 厂商(Cloudflare / Fastly / Akamai / Imperva)的 php2shell 规则;
- 监控信号:multipart 请求后紧跟 memory-limit 错误 / 500 突发、超长或 URL-encoded 的 `PHPSESSID`、worker 异常重启。

## 测试

```bash
python3 -m unittest discover -s tests
```

覆盖版本解析与判定矩阵(边界值、EOL 分支、5.4 老版本、无法识别版本等 14 项)。

## 局限

- **远程精确版本探测有天花板**:`expose_php=Off` 且无 credits 页/phpinfo 遗留/composer 泄露时,版本无法远程确认——这是 PHP 生态的客观现实(隐藏头正是为了对抗指纹)。此时可用 `--assume-vulnerable` 采取保守策略,或结合内部资产信息人工确认。
- `session.upload_progress` 探针的 "cookie 未签发" 结果可能是 SAPI/配置差异(部分 SAPI 不在该路径激活 session 钩子),报告为前置条件缺失而非"不可利用"。
- 前置 RCE 链(内存布局适配、ASLR 规避)不在扫描器范围内,本工具刻意不实现。
