# QA Agent tracing 与 SLO 契约

## 定位

`qa_core.observability` 是独立的可观测性边界：

- 生产者提交完整 span，不提交可变的 start/end 半事件。
- Journal 只负责严格校验、顺序化追加和哈希链。
- Trace-only SLO 聚合器只生成分析结果；哈希链内部自洽不能证明事件来自真实 run。
- 生产 SLO 聚合器从 run directory 现场调用 `verify_run_proof`，再读取该 root 的规范
  `agent-trace.jsonl`，并复核 terminal state、attempt、trace 路径与 SHA-256 绑定。
- `agent_slo_report.py` 是薄 CLI，负责选择 provenance 模式、约束输入、绑定现场哈希和
  写报告。

Trace 和 SLO 报告都是审计投影，不替代 lease、run state、attempt manifest 或 verdict。

## TraceEvent schema

每个事件必须精确包含以下字段；未知字段会被拒绝：

| 字段 | 约束 |
| --- | --- |
| `schema_version` | 当前固定为 `1` |
| `run_id` | 非空字符串 |
| `generation` | 正整数 |
| `iteration` | 正整数 |
| `attempt_id` | 提交前 span 可为 `null`；引用 artifact 或 terminal run 时为 `att_` 加 32 位小写十六进制 |
| `kind` | 下表中的事件类型 |
| `stage` / `action` | 非空关联名 |
| `status` | `succeeded`、`failed`、`cancelled`、`blocked` 或 `inconclusive` |
| `started_at` / `ended_at` | 带时区的 ISO 8601 时间 |
| `duration_seconds` | 必须与 start/end 精确闭合 |
| `budget` | deadline、总预算、首尾剩余预算、probe/输出用量与取消状态 |
| `reason` | 稳定 `code` 和可空 `detail` |
| `artifact_refs` | attempt、相对路径、SHA-256 和大小绑定 |
| `attributes` | 由 `kind` 判别的严格对象 |

`kind` 与 `attributes`：

| kind | attributes |
| --- | --- |
| `run` | 预期 stage/action 数量、state event 起止 sequence、是否要求 cleanup/handoff/recovery、是否收敛 |
| `stage` | 实际执行命令的 `command_sha256` |
| `action` / `cancellation` | 空对象 |
| `cleanup` | `managed_resources_remaining` |
| `handoff` | `structured` |
| `artifact_validation` | `required_ref_count`、`valid_ref_count`，且引用数量必须闭合 |
| `recovery` | `resumed`、`duplicate_committed_actions` |
| `plan_validation` | `valid_context`、`executable`、`plan_sha256`、`context_sha256` |

`run` span 的 `deadline_at` 必须等于 `started_at + total_seconds`。Trace 中的
artifact reference 只是一条内容寻址引用；实际完整性检查仍由 attempt/artifact 校验器完成，
`artifact_validation` span 记录其结果。

## Journal 完整性

`TraceJournal` 使用 JSONL，每一行是完整 `TraceRecord`：

- `sequence` 从 1 连续递增；
- 第一行 `previous_event_sha256=null`；
- 后续行绑定上一行 `event_sha256`；
- `event_sha256` 覆盖事件、sequence 和前向哈希；
- 追加在稳定 guard 文件的独占锁内完成；
- 读取在共享锁内验证 UTF-8、JSON 重复键、严格 schema、事件哈希和整条链；
- symlink、非普通文件、空行、半行、超限文件和损坏链全部失败关闭；
- 损坏的 journal 不允许继续追加。

`TraceJournal.snapshot()` 在同一次锁内返回已验证 records、原始字节 SHA-256 和大小。
外部权威 artifact 应保存该 SHA-256；仅有自包含哈希链不能证明整份文件未被完整替换。

## Terminal proof 与结果语义

`verify_run_proof` 输出 schema v2，把“证明闭合”和“允许声明通过”分开：

- `proof_valid=true` 只表示当前终局的 state、不可变 attempt、父输入、candidate
  identity、verdict、trace 与 budget 形成了闭合证明图；
- `outcome_category` 只能是 `success`、`failure` 或
  `cancellation_or_timeout`；
- 只有 `outcome_category=success` 时 `can_claim_pass` 才能为 `true`，
  `failure` 与 `cancellation_or_timeout` 固定是
  `proof_kind=terminal_observation, can_claim_pass=false`；
- 任一绑定缺失、篡改、漂移或语义冲突都会令 `proof_valid=false`，此时不暴露已验证
  outcome。

PASS 继续要求 deterministic verdict authority 和 `cycle_complete` attempt。non-PASS
观察使用独立的失败关闭根：最终 `STATUS_CHANGED` 必须由
`qa-cycle-orchestrator` 发布，并绑定当前 manifest 中最新的 `cycle_handoff`
attempt、当前父输入与 candidate identity、和 state 一致且已经 commit 的 non-PASS
verdict、同 run/generation/attempt 的 state-bound terminal trace，以及与 terminal trace
一致的 state budget。这个证明只能证明“该终局确实发生”，不能作为 PASS 证据。

这套 outcome 只属于 production SLO 的 run-proof 信任域。`qa_eval.scoring` 消费的是
独立 evaluator 签名的 observation verdict，不调用 run verifier，也拒绝 observation
中自报的 `proof_valid`、`outcome_category` 或 proof hash。最终由 release admission
分别重算这两个信任域，再通过签名中的 SLO input-set hash 连接；两边的同名结果不能
互相冒充。

## SLO 指标与词典序门

报告没有加权总分。门顺序固定为：

1. `provenance`
2. `sampling`
3. `integrity`
4. `bounded_execution`
5. `reliability`

任何前序门失败都不能被后续指标抵消，`blocking_gate` 指向最早失败门。
`provenance` 只接受全部 run root 的现场 proof 重验；自报 `input_hashes`、单独
`TraceRecord` 或 trace JSONL 都不能通过该门。

| 指标 | 计算 | 默认生产候选门 |
| --- | --- | --- |
| Deadline 超调 | 每个 run 的 `max(0, end-deadline)`，再扣除 `max(10s, budget*5%)` | p99 excess = 0 |
| 取消停止派发 | 显式 cancellation，或带精确取消/超时 reason 的 cancelled boundary；后者用完整 boundary 时长作保守上界，并扫描其后 action | p95 ≤ 2s、成功率 100%、后续派发 0 |
| 清理 | required run 与 cleanup span 配对 | 成功率 100%、p99 ≤ 10s、30s 内 100% |
| Handoff | required run 与结构化 handoff artifact 配对 | 成功率 ≥ 99.9%、p99 ≤ 15s |
| 产物完整性 | artifact validation 的有效引用数 / 必需引用数 | 100% |
| 恢复 | required run 与 recovery span 配对 | 60s 内恢复、无重复 commit，成功率 ≥ 99% |
| Plan 可执行性 | 有效 context 中一次校验可执行的比例 | ≥ 98% |
| 收敛 | deadline 内到达终局的 run 比例 | ≥ 95% |
| 可观测覆盖 | 分别比较预期/实际 stage 和 action span 数量 | 100% |

没有样本时指标值为 `null`，并产生 `*_denominator_empty` 门失败；不得把空分母输出成
`1.0`。自定义 thresholds JSON 必须提供全部字段，只能收紧生产候选阈值。

`sampling` 是不可放宽的预注册门。production 合同最少 20 个 proof-bound run，
必须覆盖 success、failure、cancellation-or-timeout；存在
`recovery_required=true` 的 run 时还必须观测 recovery。注册时间必须早于采样窗口，
窗口最长 30 天，每个 run 最大年龄 7 天，所有 run 必须位于窗口内。显式
`mode=development` 可用更小样本做测试，但绝不产生 production qualification。
类别计数只来自每个 root 的 `proof_valid` outcome；trace 内部的 failed/cancelled span
不能给另一个 `success` proof 伪造 failure 或 cancellation 样本。收敛率按 deadline 内
到达证明闭合的终局计算，因此有效 non-PASS terminal observation 是“有界完成”，但不
会被计为成功或 PASS。

## CLI

生产候选入口必须提供一个或多个 run directory：

```bash
python3 scripts/agent_slo_report.py \
  --run-dir <run-a> \
  --run-dir <run-b> \
  --candidate-identity <candidate-identity.json> \
  --sampling-contract <slo-sampling-contract.json> \
  --out <output>/agent-slo-report.json
```

CLI 对每个 root 调用 `verify_run_proof`，然后重新读取该 root 中真实的
`agent-trace.jsonl`。每个 root 必须独立得到 `proof_valid=true` 和三类 outcome 之一，
且 `can_claim_pass` 必须当且仅当 outcome 为 `success`。任一 proof 被拒绝、proof
verifier 出错、terminal state 与 outcome 冲突、attempt/budget 不匹配、trace 路径或
哈希漂移，都会产生结构化
`gate=provenance, code=run_proof_invalid` 失败。混合 valid/invalid corpus 整体失败关闭，
不会只用 valid 子集授予生产资格。

此外，每个 proof 的 `verified_refs.candidate_identity` 必须精确绑定
agent bundle、policy、ToolSpec registry、model 和 memory snapshot。聚合器只抽取该
proof 的当前 generation/iteration span，不把同一 journal 中历史 generation 当成额外
样本；任一 identity 字段缺失或与 expected candidate 不一致均失败关闭。

仅分析已有 trace 时使用：

```bash
python3 scripts/agent_slo_report.py \
  --trace <trace-a>/agent-trace.jsonl \
  --trace <trace-b>/agent-trace.jsonl \
  --out <output>/agent-slo-analysis.json
```

该模式固定输出：

- `provenance="synthetic_or_unverified"`；
- `not_production_qualified=true`；
- `qualified=false`；
- 指标门本身是否通过记录在 `analysis_qualified`。

可用 `--thresholds <thresholds.json>` 提供完整、不可弱化的预注册阈值。
`--trace` 与 `--run-dir` 互斥，防止未验证 trace 混入生产 corpus。路径 alias、symlink /
hardlink 输入、重复 JSON key、`NaN` / `Infinity`、过大 threshold 文件、过多 run roots
以及超限 trace bytes / records 都失败关闭。报告输出不得覆盖输入，也不得写入生产
run directory。

退出码：

- `0`：所有词典序门通过；
- `1`：输入有效，但至少一个门未通过；trace-only 模式固定属于此类；
- `2`：trace、threshold 或文件契约无效。

报告保存每个 trace/threshold 输入的原始 SHA-256、输入集合哈希、阈值哈希和
`report_sha256`。生产模式还保存每个 root 的 `proof_graph_sha256`、run id、trace
SHA-256、有效性和结构化失败码，因此相同已验证输入得到确定性相同报告。

## 当前接入边界

生产资格依赖 `verify_run_proof` 的当前合同：PASS 必须由 deterministic verdict
授权；non-PASS observation 必须由 orchestrator 的终局 state 与 committed handoff
授权。两者都要求当前 attempt 不可变且与 manifest 闭合、candidate identity 和父输入
current、trace snapshot SHA-256 被 state 绑定、terminal trace 引用同一 attempt，且
state/trace budget 一致。SLO 报告是这些证明的聚合投影，不替代 proof verifier、lease、
run state 或 attempt store。

`run_qa_cycle` 可通过 `--candidate-identity-registration`、
`--agent-bundle-dir`、`--candidate-policy`、`--candidate-memory-snapshot` 和
`--candidate-model-id` 启用生产身份路径。任何 QA stage 派发前，运行时会重算有界
agent bundle 文件树、policy/memory 单链接 JSON、默认 ToolRegistry 和 model id，
与预注册对象逐字段比较。它还会把实际 `run_qa_cycle.py`、实际
`playwright_probe.mjs`，以及当前进程已加载的 `qa_common`、`qa_core.*`、
`qa_eval.*` Python 源文件逐一解析到 bundle 内的规范相对路径，并把路径与文件哈希写入
schema-v2 snapshot；任一实际源码不在该 bundle 中即失败关闭。归一化 snapshot 被写入
run root，同时绑定 state component versions、attempt input hashes 和不可变 attempt
artifact。

`--agent-bundle-dir` 因而必须指向实际脚本/package 根：入口固定为
`run_qa_cycle.py` 与 `playwright_probe.mjs`，模块固定映射到 `qa_common.py`、
`qa_core/...`、`qa_eval/...`；只把更大的仓库目录作为 bundle、让实际入口藏在任意子目录
不满足执行身份合同。

在发布任何 terminal attempt 之前，运行时会稳定重读初始 snapshot，并从原始
registration、bundle、policy、memory、model、当前 ToolRegistry 和当前已加载源码集合
重新编译一次；字节哈希、来源值或源码集合任一漂移都会拒绝 attempt commit，因此该 run
不能作为该 candidate 的 PASS 或 non-PASS 生产样本。`verify_run_proof` 还会验证
execution-source 列表的闭合 schema、必需入口、规范路径与集合哈希，然后才生成
`verified_refs.candidate_identity` 和 `verified_refs.candidate_execution_sources`。

这条保证是“当前文件系统源码快照属于被哈希 bundle”，不是对已经加载的 Python
字节码、Node 进程内存、模型权重或远程推理服务的内存证明。生产 bundle 应由评测基础
设施冻结为 Agent 无写权限的只读目录；若需要进程/镜像级证明，仍须外部镜像摘要、启动
度量或可信执行证明。`--candidate-memory-snapshot` 在这里也只是冻结候选身份的 opaque
哈希，不会自动注入 ContextSnapshot、作为证据或授予动作权限；可复用运行知识只来自带
provenance、scope、expiry/revocation 和 checkpoint currentness 的 KnowledgeStore。
未启用该路径的旧 run 仍可用于普通 proof，但会在 production SLO 身份门失败关闭。
