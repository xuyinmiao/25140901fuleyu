# 实验报告：基于 ReAct 智能体与 angr 的自动化逆向分析

## 1. 实验目标

本实验将 ReAct 主循环用于简单逆向场景。LLM/Agent 负责根据目标描述和上一轮 Observation 选择下一步动作，angr 负责执行二进制分析、路径探索和约束求解。目标是分析 `crackme`，避开 `Wrong password!` 和 `trapped` 相关路径，最终到达输出 `Success!` 的状态并求出输入。

## 2. 目标程序

目标源码为 `crackme.c`，编译命令：

```bash
gcc -g -O0 -fno-stack-protector crackme.c -o crackme
```

程序逻辑包含一个死循环陷阱：

- `input[0] == 'A'`
- `input[1] == 'B'` 时进入 `gadget_trap()`
- `input[1] == 'Z'` 且后续约束满足时输出 `Success! Flag is found.`

## 3. angr 工具封装

本工程在 `agent.py` 中封装了以下工具：

1. `inspect_target()`

   使用 `angr.Project` 加载二进制，返回架构、入口地址、关键符号地址和二进制中的提示字符串。该工具为 Agent 提供语义锚点，例如 `check_password`、`gadget_trap`、`Success!`、`Wrong password!`。

2. `controlled_explore(input_len=9, max_steps=500)`

   从 `check_password` 函数入口创建符号状态，将输入缓冲区设为符号字节，约束为可打印字符。探索目标是 stdout 包含 `Success!` 的状态，避免 stdout 包含 `Wrong password!` 或 `trapped` 的状态。

3. `solve_input()`

   在 `controlled_explore` 找到成功状态后，从该状态的 solver 中求解符号输入。为了避免把无关后缀当作必要密码，该工具会检查每个字节是否唯一受约束，并输出最小必要前缀。

4. `verify_candidate(candidate)`

   运行真实 `crackme`，将候选输入写入 stdin，确认是否触发成功输出。该工具用于结果验证，不是 angr 工具。

## 4. ReAct 主循环

`AgentRunner` 维护消息历史，并执行如下闭环：

1. LLM 或 mock LLM 输出 `Thought`、`Action`、`Action Input`。
2. `parse_json_action` 或 OpenAI tool calling 解析动作。
3. `dispatch` 将动作派发到对应工具。
4. 工具返回结构化 JSON Observation。
5. Observation 写回消息历史，并记录到 `logs/react_run.md`。

目标和约束在系统提示中显式描述：优先到达包含 `Success!` 的输出路径，避免 `Wrong password!` 和 `trapped` 路径。

## 5. 运行日志摘要

完整日志见 `logs/react_run.md`，关键 4 轮如下：

| 轮次 | Thought 摘要 | Action | Observation 摘要 |
| --- | --- | --- | --- |
| 1 | 检查目标架构、符号和关键字符串 | `inspect_target({})` | 发现 `check_password`、`gadget_trap`、`Success!`、`Wrong password!`、`trapped` |
| 2 | 从 `check_password` 做受控符号执行 | `controlled_explore({"input_len": 9, "max_steps": 500})` | 17 步找到输出 `Success!` 的状态，避开 4 条错误/陷阱路径 |
| 3 | 从成功状态求解输入 | `solve_input({})` | 求得最小必要前缀 `AZcE` |
| 4 | 运行真实程序验证候选输入 | `verify_candidate({"candidate": "AZcE"})` | 输出 `Enter password: Success! Flag is found.` |

## 6. 实验结果

求得的有效输入为：

```text
AZcE
```

实际运行验证：

```text
Enter password: Success! Flag is found.
```

## 7. 思考题

在本实验中，LLM 主要承担高层决策和编排角色。它不直接替代 angr 做指令级符号执行，而是根据二进制中的字符串、函数名和上一轮 Observation 判断下一步该调用哪个工具。

纯符号执行容易在无关分支、错误分支和死循环路径上浪费大量状态。LLM 可以利用语义与常识进行搜索指导，例如看到 `Success!` 就把它作为 find 条件，看到 `Wrong password!` 和 `trapped` 就把它们作为 avoid 条件。这样，angr 仍然负责严密的路径约束和输入求解，LLM 则减少盲目搜索，使探索更接近人工逆向时的分析流程。

## 8. 说明

本机没有配置 OpenAI API key，因此提交日志使用 `--llm mock` 生成稳定 ReAct 决策；真实路径探索、状态约束和输入求解均由 angr 执行。若需要真实大模型工具调用日志，可设置 `OPENAI_API_KEY` 和 `OPENAI_MODEL` 后运行：

```bash
.venv/bin/python agent.py --llm openai --binary ./crackme --log logs/react_run.md
```
