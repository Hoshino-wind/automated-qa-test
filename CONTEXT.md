# 项目上下文：Proof-carrying QA Agent

> 状态：稳定的项目语境与硬约束。详细的 v2 生产候选架构见
> [`docs/architecture/agent-v2.md`](docs/architecture/agent-v2.md)。

## 核心目标

本项目要构建的是一个 **proof-carrying QA Agent（携证 QA Agent）**：

> 在明确的环境、数据和资源边界内，把需求编译为可执行验证，主动寻找高价值反例，
> 并让每个结论都携带可重放、可审计、与本轮输入哈希绑定的证据。

优化目标不是“尽可能多地执行测试”，而是在安全约束下最大化：

```text
有效缺陷发现 + 对未发现缺陷的可信覆盖
────────────────────────────────────
时间 + 模型成本 + 工具调用 + 人工介入
```

安全性和证据完整性是约束，不参与加权交换。任何更高的覆盖率、速度或模型能力都不能
抵消一次不合法的 `PASS`。

## 当前事实

- 正常执行入口是 `skills/automated-qa-test/scripts/run_qa_cycle.py`；它串联需求覆盖、
  预检、Adapter、当前上下文、计划、探针、证据、清理和结论阶段。
- `skills/automated-qa-test/scripts/qa_agent_loop.py` 在一个 run directory 上执行有界迭代，
  共享同一个 `RunBudget` 和 generation-fenced lease，并生成机器可读路由和人类 handoff。
- 单写 lease、不可变 attempt、追加式 state event journal、当前 context 哈希和
  `agent-trace.jsonl` 已进入独立 proof graph；摘要和报告仍只是投影。
- 每个真实探针 action 都从默认 `ToolSpec` registry 派生严格合同，先在
  `action-journal.jsonl` 落 durable intent，执行后再落 commit。未决非幂等 intent
  只能转人工 reconciliation。
- 受约束 Planner、Diagnostician、Critic 和 Scheduler 已提供严格公共合同；
  Diagnostician 只能更新当前计划中的假设并引用当前 trace/证据，所有输出都只是建议；
  `not_authorization=true`，并行建议不构成运行时授权。
- HITL 和跨运行 Knowledge 使用 Ed25519 人工收据、可信时钟、精确 scope/currentness
  和一次性消费；production journal 还必须验证外部 authority 签名且精确覆盖当前
  journal 的 anti-rollback checkpoint。未覆盖 tail 不能用于 query/resume/consume，
  production consume 需经“持久化 prepare—外部 checkpoint—resume 确认”两阶段。
  Knowledge 始终是 `not_evidence=true`。
- 生产 SLO 只接受现场重验通过的 run roots。独立 evaluator registration 与联合
  release admission 已实现，但仓库自身没有外部 held-out corpus、私钥或独立
  authority，因此不能自证 production qualified。
- Adapter 严格 onboarding、每日浏览器/非浏览器矩阵和离线故障注入均已形成公开维护
  合同；它们是工程门禁，不是产品运行证据。
- `results.json`、`evidence-ledger.json`、审计结果和确定性 verdict 是通过声明的业务
  证据链；run proof 还必须闭合 state、manifest、attempt、trace、action 和当前输入。
- 业务模型、Oracle、指标、报告和模型推理可以辅助规划与解释，但它们本身不是运行证据。
- 合法测试状态是 `Passed`、`Failed`、`Blocked`、`Untested` 和 `Inconclusive`。
- `--skip-probe` 仅用于 planning/blocker handoff；它不派发 action、不可形成
  `can_claim_pass=true`。

## 事实、假设与待验证命题

### 事实

- 模型输出可能错误、不完整、受提示注入影响，也可能在相同输入下产生不同结果。
- 外部服务、浏览器、网络和子进程可能超时、崩溃或产生部分输出。
- 文件写入原子性不能自动提供跨阶段事务、并发所有权或产物新鲜度。
- 一个结论只有在其输入、执行过程和证据来源可验证时才具有交付价值。

### 工作假设

- Agent 运行在获得明确授权的测试环境，默认不接触生产数据或生产凭据。
- 项目可以提供需求、代码快照和最小运行说明；缺失信息应形成显式 blocker。
- 模型适合提出假设、计划和修复建议；确定性内核负责授权、执行和判定。
- 大多数失败可以通过结构化事件、不可变产物和幂等恢复被定位或重放。

### 待验证命题

- 受约束的 Planner/Diagnostician/Critic 能在相同预算内显著提高 held-out 缺陷发现率。
- 项目语义编译能减少脆弱的需求关键词匹配，同时保持计划可解释性。
- 人工确认后的跨运行知识能降低重复探索成本，且不会污染证据判定。

待验证命题必须通过独立评测确认，不能写成产品事实。

## 硬约束

1. 默认失败关闭：缺失、陈旧、格式错误或无法审计的证据只能导向非通过。
2. 最小权限：工具只访问声明的目录、服务、凭据和数据边界。
3. 有界执行：每个 run、stage 和工具调用都有预算、deadline 和取消路径。
4. 可重放：重要结论能从版本化输入、策略、工具收据和证据哈希重建。
5. 可解释 handoff：无法继续时必须说明阻断层、原因、所需输入和下一安全动作。
6. 模型与裁决分离：概率推理可以建议，不能直接授权工具或生成可解锁的 `PASS`。
7. 评测独立：生产候选必须通过与开发语料隔离的 held-out 合同，不能只依赖自编案例。
8. 外部锚定：生产 HITL/Knowledge 与生产评测所需私钥、语料和 authority 必须位于
   Agent 写边界之外；本地哈希链或自签结果不能替代外部信任根。

## 四个不可变式

### 1. 单写者

每个 run 在任一时刻只有一个持有效 lease 的逻辑写入者。所有权必须包含
`run_id`、owner、generation 和过期信息；没有 lease 的进程不能提交权威产物。

### 2. 输入哈希绑定

每个计划、执行收据、证据、审计和 verdict 都必须记录直接父输入的内容哈希。
“当前”由哈希关系决定，而不是由文件名存在、修改时间或模型判断决定。

### 3. 旧产物不得解锁 `PASS`

历史报告、旧 verdict、旧 results、旧 ledger 或旧语义模型可以用于诊断，不能进入本轮
通过判定。所需本轮证据缺失时，唯一合法结果是非通过。

### 4. 模型不可绕过执行策略

模型只能提交 proposal。只有确定性的策略引擎能把 proposal 转为带授权令牌的
validated plan；执行器拒绝任何未通过策略校验、超出能力或哈希不匹配的动作。

Scheduler、Critic、SLO 报告、评测报告和 P2 release admission 都不得被解释成单个
工具或 action 的运行时授权。

## 稳定术语

- **Run**：一次顶层 QA 任务，拥有独立 `run_id`、预算和 lease。
- **Iteration**：同一 run 内的一轮“计划—执行—审计—修复”。
- **Attempt**：一个 stage 或工具动作的具体执行实例；重试产生新的 attempt。
- **Proposal**：模型或规则提出、尚未获准执行的计划或增量。
- **Validated plan**：经 schema、策略、能力和预算校验后可执行的计划。
- **Receipt**：执行器对实际动作、环境、时间、退出状态和输出哈希的记录。
- **Action contract**：从当前 plan/context/audit 与 `ToolSpec` 派生的单 action
  调用、风险、授权和恢复合同。
- **Action journal**：先 intent、后 commit 的追加式 action dispatch 日志；用于证明
  派发覆盖和恢复边界。
- **Evidence**：与 receipt 和当前输入绑定、能够证明或反驳测试断言的观察。
- **Verdict**：确定性判定器基于已审计证据生成的终局状态。
- **Projection**：面向人或外部编排器的报告、摘要和 handoff；不是权威状态源。
- **Proof-carrying claim**：携带 scope、run、输入哈希、证据引用和策略版本的结论。
- **Release admission**：对“由独立签名 evaluator registration 约束的 production
  evaluation”与 proof-backed SLO 的派生联合发布门；它自身不是签名凭据，只适用于
  声明的 P2 release scope，也不是 runtime authorization。

## 当前生产资格边界

当前实现具备 production qualification 所需的验证器和失败关闭门，但没有声称已经获得
生产资格。真实资格至少需要：

1. Agent 无写权限的 200 scenario × 3 seed held-out corpus、gold oracle 和 deterministic
   baseline；
2. 独立 evaluator authority 对 corpus、candidate、baseline、预算、阈值和 SLO input set
   的 Ed25519 registration；
3. 来自实际目标环境、逐个得到 `proof_valid=true` 的 run roots；其 outcome 必须为
   success、failure 或 cancellation-or-timeout，且只有 success 可以
   `can_claim_pass=true`；
4. `agent_release_admission.py` 对 evaluation 与 SLO 的现场重算和交叉哈希闭合。

即使 release admission 成功，P2 并行/多 Agent 也只获得发布范围内的资格结论；
Scheduler/Critic 建议和 admission 都不会自动签发工具授权，现有单 run 单写者约束保持
不变。

## 决策优先级

发生冲突时按以下顺序取舍：

1. 人员、数据、凭据和生产环境安全；
2. 四个不可变式与 verdict 完整性；
3. 可恢复性、可审计性和确定性 handoff；
4. 缺陷发现能力与覆盖率；
5. 延迟、模型成本和开发便利性。
