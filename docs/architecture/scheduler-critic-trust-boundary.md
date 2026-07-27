# Scheduler / Critic 信任边界

Scheduler 与 Critic 都只产生建议，不是执行器、Policy 或授权签发者。它们的所有成功
输出都包含 `not_authorization: true` 和 `admission_allowed: false`；并行批次仅表示
候选组合建议，不能当作并行执行许可。真正执行前仍必须由执行器独立验证当前、
未过期且与 invocation、context、state、plan、budget 和 ToolSpec 绑定的
`ExecutionAuthorization`。

## Scheduler

Scheduler 请求只能为候选提供以下不可信 proposal 字段：

- `id`、`action`、`tool_version`、`tool_spec_sha256`；
- 成本、时间、信息增益估计；
- 候选依赖。

请求不得提供 `risk_class`、`idempotent`、`capabilities`、`read`、`write`、
`side_effects` 或授权哈希。Scheduler 会用内置默认 `ToolRegistry` 重新解析 action，
验证 registry/spec/version 哈希，再从匹配的 `ToolSpec` 派生上述安全元数据。
未知 action、版本或哈希漂移均失败关闭。

资源冲突采用保守的 namespace 祖先规则。`db/users` 与 `db/users/42`、父目录与子路径、
同一 URL host 下的父路径与子路径均冲突；URL host、默认端口和路径会先规范化。
非幂等动作、critical 动作以及 high/critical 风险的 mutation 默认只能进入串行建议。

成本、时长、动作数、并行度和信息增益均有有限业务上限。累计采用受检 `fsum`；
溢出或非有限结果返回结构化 contract error。

## Critic

Critic 候选不接受调用方提供的 `probe_fingerprint_sha256`。它先以默认
`ToolRegistry` 验证 action、canonical arguments、tool version 和 spec hash，再按
以下规范对象内部计算指纹：

```json
{
  "action": "...",
  "arguments": {},
  "tool_version": "...",
  "tool_spec_sha256": "..."
}
```

因此，改变 action、任一参数、工具版本或规格都会改变指纹，调用方不能通过自报新
指纹绕过重复探针检测。

当前 Critic 尚未接入可独立验证的不可变 history journal，所以请求中的 `history`
一律标为 `history_authoritative: false`。非权威历史不会解除 anti-repeat；所有候选
都应用保守 duplicate/no-progress floor，成功建议使用
`consider_with_unverified_history`，提醒上层不得把该历史当作执行或进展事实。

## CLI 输入边界

`agent_schedule_cli.py` 与 `agent_critic_cli.py`：

- 使用严格 JSON，拒绝 duplicate keys、`NaN` 和 `Infinity`；
- request 最大 1 MiB；
- 仅以 `O_NOFOLLOW` 打开普通文件，拒绝符号链接；
- 所有已知输入错误输出结构化 JSON，不打印 Python traceback；
- 输出路径不得覆盖或别名引用 request。

