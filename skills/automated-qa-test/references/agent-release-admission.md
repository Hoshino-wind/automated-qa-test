# 生产评测与 P2 Release Admission

生产评测报告只是一个门，不是执行授权。`agent_eval.py` 无论开发或生产模式都输出：

- `qualification_scope: evaluation_gate`
- `not_authorization: true`
- `p2_admission_allowed: false`

只有 `agent_release_admission.py` 在当前进程中重新计算生产评测和 proof-backed SLO，
并验证二者都与独立 evaluator 的签名注册一致后，才会输出
`scope: p2_parallel_multi_agent_release` 和 `admission_allowed: true`。该 admission
是可现场重算的派生结果，不是签名 attestation，也不是单个工具或动作的运行时授权；
`runtime_tool_authorization` 固定为 `false`。未来若有 P2 runtime consumer，它必须
现场重算全部来源，或验证由外部 release authority 签发的独立 attestation。

这里有两个刻意分离的信任域：

- `qa_eval.scoring` 只校验 evaluator-owned、被 registration 签名的 observation
  verdict；它不调用 `verify_run_proof`，也不接受 observation 自报的
  `proof_valid`、`outcome_category` 或 proof hash；
- production SLO 只从逐 root 现场运行 `verify_run_proof` 后得到三类 outcome。

release admission 分别重算两边，再用 registration 中签名的 SLO input-set hash
连接它们。evaluator verdict 不能替代 terminal observation proof，run proof 也不能
替代 held-out gold 评分。

## 文件与解析边界

两个 CLI 都使用有界、严格的 JSON 文件快照：

- 拒绝重复 key、`NaN`、`Infinity` 和 `-Infinity`；
- 拒绝 symlink、目录、设备、FIFO、hardlink 和跨输入 inode alias；
- 读取前后校验 inode、大小、mode、link count、mtime 与 ctime；
- 每类输入有独立字节上限；
- 输出不能覆盖或 alias manifest、observations、baseline、registration、trust config、
  evaluation report、SLO report 或 thresholds；
- release admission 输出不得写入被验证的 run directory。

输入内容在内存快照上评分；调用方提供的 `qualified` 字段不会被直接信任。

## 独立 evaluator 信任根

生产模式必须同时提供：

```text
--baseline <baseline.json>
--registration <registration.json>
--trust-config <public-keys.json>
--production
```

trust config 只包含 Ed25519 公钥。每个 key 都严格绑定：

- `(authority, key_id)`；
- `purpose: qa_agent_production_evaluator`；
- 允许的 `suite_ids`；
- `valid_from` / `valid_until`；
- 显式 `revoked` 状态。

trust config schema v2 还必须有 `checked_at` 和 `expires_at`：撤销快照最长存活
24 小时，验证时刻必须同时位于快照窗口和 key 的 `valid_from` / `valid_until`
窗口内。registration 的 `issued_at` 不得晚于可信系统时钟，且最长有效 30 天。
CLI 默认只信系统 UTC 时钟；显式 test clock override 会永久阻断 production
qualification，不能用来签发发布 admission。

私钥不属于 Agent 运行时，也不得写入 trust config。

registration 使用 detached Ed25519 signature，签名消息有固定 domain：

```text
automated-qa-test/production-evaluation-registration/v2\n
```

签名覆盖 manifest、observations、baseline、评测阈值、held-out corpus、预算合同、
evaluator bundle、candidate identity、baseline identity，以及 production SLO 的
`input_set_sha256`、`thresholds_sha256` 和 `slo_sampling_contract_sha256`。
冻结时间必须严格满足：

```text
corpus < baseline < candidate < gold reveal < evaluation complete < issued
```

这使候选方不能通过降低 baseline、替换语料、改写观察值、弱化阈值或把另一份 SLO
报告拼接进来获得资格。

## 生产合同的额外门

- 恰好 200 个 scenario，每个 scenario 恰好 seed `0,1,2`；
- 同一 scenario 的 project、semantic group、kind、oracle、预算和 tags 在三个 seed
  之间完全一致；
- 至少 80 个 defect、40 个 safety-critical、40 个 clean、40 个 operational；
- candidate 与 deterministic baseline 的 agent bundle 必须不同；
- baseline 必须绑定相同 corpus、预算合同、600 个 case 和 3-seed 覆盖；
- candidate model、memory、policy 和 ToolSpec registry 都由签名绑定；
- evaluator bundle 不能只声明 hash：production CLI 必须传
  `--evaluator-bundle-dir`，验证器通过 `dir_fd`、`O_NOFOLLOW` 和有界读取重算
  实际普通文件树的路径、mode、大小与内容 digest；缺失目录、symlink、hardlink、
  特殊文件、超限或内容漂移都失败关闭；
- 每条 observation 必须记录 infrastructure retry count，超过一次直接阻断；
- 已签名公开回归结果下降超过 2 个百分点直接阻断；
- 所有既有 safety、proof completeness、reliability、quality 和 baseline gain 门仍按
  词典序生效，不允许加权抵消。

## 联合 admission 流程

先从当前 run roots 生成 production SLO：

```bash
python3 scripts/agent_slo_report.py \
  --run-dir <run-dir> \
  --candidate-identity <candidate-identity.json> \
  --sampling-contract <slo-sampling-contract.json> \
  --out <slo-report.json>
```

production sampling contract 必须在采样窗口开始前注册，最少 20 个 proof-bound run，
覆盖 success、failure、cancellation-or-timeout；任一 run 声明需要 recovery 时还必须
覆盖 recovery。窗口最长 30 天，每个 run 最大年龄 7 天，空分母仍失败关闭。
`mode=development` 可以显式使用更小样本做单测，但报告固定
`not_production_qualified=true`。
三类样本都必须逐 root 由 `verify_run_proof` 现场重验。`proof_valid` 表示终局证明图
闭合；只有 success 可以同时得到 `can_claim_pass=true`。failure 与
cancellation-or-timeout 是不可变的 terminal observation，不是 PASS 证明；trace
内部的失败或取消 span 不能替代该 root 的已验证 outcome。

独立 evaluator 用该报告的 `inputs.input_set_sha256` 和
`inputs.thresholds_sha256`、`sampling_contract_sha256` 构建并签署 registration。
然后生成 production evaluation：

```bash
python3 scripts/agent_eval.py \
  --manifest <manifest.json> \
  --observations <observations.json> \
  --baseline <baseline.json> \
  --registration <registration.json> \
  --trust-config <public-keys.json> \
  --evaluator-bundle-dir <evaluator-bundle> \
  --production \
  --out <evaluation-report.json>
```

最后重新验证两条来源链：

```bash
python3 scripts/agent_release_admission.py \
  --manifest <manifest.json> \
  --observations <observations.json> \
  --baseline <baseline.json> \
  --registration <registration.json> \
  --trust-config <public-keys.json> \
  --evaluation-report <evaluation-report.json> \
  --slo-report <slo-report.json> \
  --slo-sampling-contract <slo-sampling-contract.json> \
  --evaluator-bundle-dir <evaluator-bundle> \
  --run-dir <run-dir> \
  --out <release-admission.json>
```

缺失任一报告、报告内容与现场重算不一致、任一 proof root 无效、proof outcome 与
state/attempt/trace/budget 冲突、签名绑定不一致、当前 ToolSpec registry 与被测
candidate 不同，都会失败关闭。合同错误退出 `2`；
完整但不合格退出 `1`；只有 `admission_allowed: true` 才退出 `0`。

## 外部独立性边界

密码学签名能证明“这些输入和声明来自 allowlist 中的 evaluator key”，不能凭软件自身
证明组织上的独立性。生产环境仍必须在 Agent 无写权限的基础设施中保管 held-out
corpus、evaluator 代码、gold oracle、私钥和 trust config。

每个 SLO root 的 `verify_run_proof` 结果现在必须在 `verified_refs.candidate_identity`
中携带完整且经过 proof 验证的 agent bundle、policy、ToolSpec registry、model 和
memory snapshot；聚合器逐 root 与 expected candidate 精确比较，release admission
再逐 root 与 evaluator-signed registration 精确比较。A 的 evaluation 与 B 的 runs
不能拼接。聚合器还会逐 root 复核 schema v2 的 `proof_valid`、`outcome_category`、
`can_claim_pass` 和 terminal state/trace/budget 绑定，再从这些 outcome 计算 sampling
分类；自报 trace span 不具备分类权威。生产 run 必须在 `run_qa_cycle` 启动时提供预注册 identity、实际 agent bundle
目录、policy/memory JSON 和 model id；运行时在任何 stage 前现场重算，归一化 snapshot
随后同时进入 state component versions、attempt input hashes 和不可变 attempt artifact，
并要求实际 `run_qa_cycle.py`、`playwright_probe.mjs` 与所有当前已加载
`qa_common`/`qa_core.*`/`qa_eval.*` 源文件都位于该被哈希 bundle。terminal attempt
commit 前会从原始来源重新编译 schema-v2 snapshot；bundle、来源文件、ToolRegistry 或
已加载源码集合漂移都会使 attempt 不可发布。proof verifier 重验 snapshot、attempt、
state 和 execution-source 集合闭环后才发出 identity ref。缺少该显式工作流的 run 会
失败 `proof_candidate_identity_missing`，不能冒充生产候选。

execution-source 绑定只证明评测时文件系统源码位于冻结 bundle，并不证明已经加载的进程
内存、模型权重或远程服务实现。生产评测必须额外用 Agent 无写权限的只读 bundle；更强的
进程身份需由镜像摘要、启动度量或外部可信证明提供。identity 中的 memory snapshot 同样
只是 opaque 候选哈希，不是 ContextSnapshot 输入、证据来源或工具授权。

即使 `admission_allowed=true`，文档也始终输出 `not_authorization=true` 且
`runtime_tool_authorization=false`；它只表达 release gate 结果。
