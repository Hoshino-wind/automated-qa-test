# 自动化 QA-Test

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

这是一个面向 Codex 的自动化测试 Skill，用于对 Web 应用和 API 做严格的、需求驱动的 QA 测试。

它的核心目标是：让 Codex 从需求、Issue、PR 或 Bug 描述中提取测试点，生成测试矩阵，执行浏览器/API 探测，维护证据账本，并在生成报告前做证据审计，避免编造数据或把未测试内容写成通过。

## Skill 名称

```text
$automated-qa-test
```

## 适合什么场景

- 根据一段需求描述做功能测试。
- 根据 GitHub Issue 或 PR 做验收测试。
- 检查功能逻辑是否通。
- 检查交互是否正常，例如按钮、弹窗、表单校验、加载态、错误提示。
- 检查接口/API 是否正常返回。
- 检查数据是否从输入、接口、持久化到页面展示形成闭环。
- 捕获 console error、network 4xx/5xx、截图和报告证据。
- 生成严格区分 `Passed / Failed / Blocked / Untested / Inconclusive` 的测试报告。

## 设计原则

这个 Skill 不会固化某个项目的页面、路由、接口或业务规则。

每次测试时，Codex 应该从本次输入中动态推导测试范围：

- 用户直接写的需求
- GitHub Issue
- GitHub PR
- Bug 描述
- 验收标准
- 当前代码和运行时行为

重点是：**没有证据，不能判定通过。**

## 安装

把 Skill 目录复制到 Codex 的 skills 目录：

```bash
mkdir -p "${CODEX_HOME:-$HOME/.codex}/skills"
cp -R skills/automated-qa-test "${CODEX_HOME:-$HOME/.codex}/skills/"
```

如果 Codex 没有自动刷新 Skill 列表，重启 Codex。

也可以通过 Codex 的 skill installer 安装：

```bash
python3 "${CODEX_HOME:-$HOME/.codex}/skills/.system/skill-installer/scripts/install-skill-from-github.py" \
  --repo Hoshino-wind/automated-qa-test \
  --path skills/automated-qa-test
```

## 使用方式

对 Codex 说：

```text
Use $automated-qa-test to strictly test this requirement. Do not fabricate data. Every Passed item must have evidence.
```

中文也可以这样说：

```text
使用 $automated-qa-test 严格测试下面这个需求。
要求：
- 不能遗漏需求点
- 禁止编造数据
- 每个 Passed 必须有当前运行证据
- 没测到的写 Untested
- 测不了的写 Blocked
- 证据不足的写 Inconclusive
```

示例需求：

```text
使用 $automated-qa-test 测试这个 Issue：
- 用户可以提交表单
- 接口返回 200
- 创建的数据会出现在列表中
- 表单校验和错误提示正常
- 不允许编造数据
```

## 标准工作流

1. 创建本次测试运行目录。
2. 读取需求、Issue 或 PR。
3. 提取需求点，生成 `test-matrix.json`。
4. 生成或修改 `test-plan.json`。
5. 用 Playwright runner 执行浏览器/API 探测。
6. 根据当前运行的截图、接口、日志、网络请求填写 `evidence-ledger.json`。
7. 运行 `audit_evidence.py` 做证据审计。
8. 生成 Markdown 测试报告。

## 运行产物

一次测试运行通常包含：

```text
<run-dir>/
├── requirement.md
├── test-charter.md
├── test-matrix.json
├── test-plan.json
├── results.json
├── evidence-ledger.json
├── audit-summary.json
├── screenshots/
└── report.md
```

## 常用脚本

进入 Skill 目录：

```bash
cd skills/automated-qa-test
```

初始化测试运行目录：

```bash
python3 scripts/init_qa_artifact.py \
  --requirement-text "用户可以提交表单，并在列表中看到保存后的数据。" \
  --base-url http://127.0.0.1:3000
```

执行 Playwright 探测：

```bash
node scripts/playwright_probe.mjs --plan /path/to/run/test-plan.json
```

运行证据审计：

```bash
python3 scripts/audit_evidence.py \
  --matrix /path/to/run/test-matrix.json \
  --ledger /path/to/run/evidence-ledger.json \
  --summary /path/to/run/audit-summary.json
```

生成报告：

```bash
python3 scripts/generate_report.py \
  --plan /path/to/run/test-plan.json \
  --results /path/to/run/results.json \
  --requirement /path/to/run/requirement.md \
  --ledger /path/to/run/evidence-ledger.json \
  --audit-summary /path/to/run/audit-summary.json \
  --out /path/to/run/report.md
```

## 状态定义

需求点只能使用以下状态：

- `Passed`：已用当前运行证据直接证明。
- `Failed`：已测试，并且证据证明不符合预期。
- `Blocked`：因为明确阻塞原因无法测试。
- `Untested`：本次没有测到。
- `Inconclusive`：有证据，但证据不足或互相矛盾，无法判定通过或失败。

## 证据规则

`Passed` 必须有直接证据。证据可以是：

- 截图
- API 响应
- HTTP 状态码
- 返回字段
- 后端日志
- console/network 记录
- 页面可见文本
- 数据库或持久化检查结果

如果需求涉及数据链路，不能只因为 UI 看起来正常就判定通过。需要进一步验证 API、返回数据、持久化或日志。

## 审计失败条件

`audit_evidence.py` 会在以下情况失败：

- 需求点没有映射测试项。
- 测试矩阵里的需求或测试没有出现在证据账本里。
- `Passed` 的需求没有证据。
- `Passed` 的测试没有证据。
- 需求或测试引用了不存在的证据。
- 截图/文件证据路径不存在。
- 非 Passed 状态没有说明原因。

## 许可证

MIT
