# Agent Proposal / Policy CLI

`scripts/agent_policy_cli.py` 是 Tool Registry 与现有 runner 之间的旁路安全入口。它只验证
proposal、签发授权和验签，**不会执行浏览器、命令或网络动作**。

## 1. 固定 Registry

查看默认 runner action、规格和规范哈希：

```bash
python3 scripts/agent_policy_cli.py registry \
  --out /tmp/qa-tool-registry.json
```

proposal 的 `tool_registry_sha256` 必须等于该输出中的同名字段。默认 Registry 与
`playwright_probe.mjs` 的 action dispatcher 一一对应；`validate_plan.py` 也使用同一个
allowlist，因此未知 action 会在 Node runner 启动前失败。

Registry 对模型开放的是 runner 的安全子集，不是旧计划字段的宽松透传：

- 所有 input/output schema 都是关闭的 object；
- `command` 只接受字符串数组，不接受 shell 字符串或 `shell` 字段；
- 风险、权限、timeout、输出上限和副作用都由 ToolSpec 明确声明；
- `wait`、`waitForLoadState` 是控制动作，不被当作 evidence-producing step。

## 2. Proposal 形状

最小 `goto` proposal：

```json
{
  "proposal_id": "plan-goto",
  "context_sha256": "<64-char-sha256>",
  "state_sha256": "<64-char-sha256>",
  "tool_registry_sha256": "<registry-sha256>",
  "model_id": "planner-model@version",
  "objective": "观察当前测试环境中的结算入口",
  "hypotheses": [
    {
      "hypothesis_id": "H1",
      "statement": "结算入口可以在隔离环境打开",
      "evidence_refs": ["requirement.md#R1"]
    }
  ],
  "evidence_refs": ["requirement.md#R1"],
  "probes": [
    {
      "probe_id": "P1",
      "context_sha256": "<64-char-sha256>",
      "state_sha256": "<64-char-sha256>",
      "tool_registry_sha256": "<registry-sha256>",
      "model_id": "planner-model@version",
      "hypothesis_ids": ["H1"],
      "evidence_refs": ["requirement.md#R1"],
      "rationale": "收集当前运行页面证据",
      "invocation": {
        "action": "goto",
        "arguments": {"path": "/checkout"}
      },
      "timeout_seconds": 20,
      "output_limit_bytes": 65536
    }
  ]
}
```

模型只能产生 `PlanProposal` / `ToolInvocation`。任何层级的 `authorization`、`signature`
或 `shell` 字段都会失败，模型也不能自行提供 ToolSpec version 或哈希。

## 3. 策略验证

HMAC key 只能从环境变量读取，不提供明文命令行参数。生产环境应由 secret manager 注入
至少 32 字节的 `QA_POLICY_HMAC_KEY`。

```bash
python3 scripts/agent_policy_cli.py validate \
  --proposal /tmp/goto-proposal.json \
  --probe-id P1 \
  --context-sha256 "<current-context-sha256>" \
  --state-sha256 "<current-state-sha256>" \
  --model-id "planner-model@version" \
  --evidence-ref "requirement.md#R1" \
  --grant isolated_test_environment \
  --max-risk low \
  --total-timeout 60 \
  --max-probes 1 \
  --max-output-bytes 1048576 \
  --out /tmp/goto-decision.json
```

本地 `command` proposal 还必须：

- 使用 `{"command": ["program", "arg"]}` 数组；
- 传入 `--grant command_execution`；
- 使用 `--max-risk high`；
- 同时保留 `--grant isolated_test_environment`。

CLI 依次检查 proposal schema、调用方选择的精确 model id、调用方注入的 evidence ref
allowlist、当前 context/state/registry 哈希、ToolInvocation、风险、权限、ToolSpec
timeout/output 上限和 RunBudget。假设与探针只能引用顶层 proposal 已声明且位于
allowlist 中的来源。只有全部通过，decision 才包含
`ExecutionAuthorization`。

`validate` 只检查预算快照，不消费额度；实际 executor 在执行前仍必须原子预留 probe、
时间和输出额度。

## 4. 独立验签

把 decision 中的 `authorization` object 单独保存后，由 executor 边界独立验证：

```bash
python3 scripts/agent_policy_cli.py verify \
  --proposal /tmp/goto-proposal.json \
  --probe-id P1 \
  --authorization-file /tmp/goto-authorization.json \
  --context-sha256 "<current-context-sha256>" \
  --state-sha256 "<current-state-sha256>" \
  --model-id "planner-model@version" \
  --evidence-ref "requirement.md#R1" \
  --policy-version qa-default-policy@1 \
  --out /tmp/goto-verification.json
```

验签同时检查 HMAC、有效期、policy、context/state、registry、ToolSpec、plan、probe、
invocation 和 executor version。任一载荷或签名变化都会得到 `verified=false`。

## 5. 退出码

- `0`：Registry 输出成功、策略允许，或授权验签通过；
- `1`：输入、proposal、schema、配置或 HMAC key 错误；
- `2`：proposal 合法但策略拒绝，或授权验签失败。

`--now` 仅用于可重放离线评测。正常运行应省略，让 CLI 使用当前 Unix 时间。
