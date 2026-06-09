# ReAct Agent + angr Crackme Lab

本工程实现 PDF 作业要求的实验：用 ReAct 主循环调度 angr 工具，自动探索 `crackme` 的成功路径并求解输入。

## 文件说明

- `crackme.c`：测试目标源码。
- `crackme`：本机已编译的 Mach-O arm64 测试目标。
- `agent.py`：ReAct 主程序，包含 LLM 输出解析、工具派发、Observation 构造。
- `requirements.txt`：Python 依赖。
- `logs/react_run.md`：不少于 3 轮的 Thought -> Action -> Observation 运行日志。
- `report.md`：实验报告和思考题回答。

## 环境安装

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

## 编译目标程序

```bash
make
```

等价命令：

```bash
gcc -g -O0 -fno-stack-protector crackme.c -o crackme
```

Linux 上如果希望地址更固定，可以追加 `-no-pie`。

## 运行离线可复现版本

```bash
.venv/bin/python agent.py --llm mock --binary ./crackme --log logs/react_run.md
```

该模式使用项目内置的 `ScriptedToolCallingClient` 产生稳定的 ReAct 决策，便于没有 API key 时复现实验闭环。真正的符号执行与输入求解仍由 angr 完成。

## 运行真实 DeepSeek Tool Calling 版本

DeepSeek API 兼容 OpenAI SDK，默认使用：

- base URL: `https://api.deepseek.com`
- model: `deepseek-v4-flash`

```bash
export DEEPSEEK_API_KEY="你的 DeepSeek key"
.venv/bin/python agent.py --llm deepseek --binary ./crackme --log logs/react_run_deepseek.md
```

如果账号暂时不能使用 `deepseek-v4-flash`，可切换模型：

```bash
export DEEPSEEK_MODEL="deepseek-chat"
.venv/bin/python agent.py --llm deepseek --binary ./crackme --log logs/react_run_deepseek.md
```

## 运行真实 OpenAI Tool Calling 版本

```bash
export OPENAI_API_KEY="你的 key"
export OPENAI_MODEL="支持 tool calling 的模型名"
.venv/bin/python agent.py --llm openai --binary ./crackme --log logs/react_run.md
```

`--llm openai` 会调用 Chat Completions tool calling，由模型选择工具；工具调用结果会继续写入同一份日志文件。

## 当前求解结果

angr 找到的成功路径约束给出最小有效输入前缀：

```text
AZcE
```

验证输出：

```text
Enter password: Success! Flag is found.
```
