# ReAct Agent 静态二进制漏洞分析实验

这个项目实现一个 ReAct Agent：LLM 负责编排，`radare2` 和 `Ghidra` 作为只读工具，对 `targets/challenge` 做静态分析，最后生成 `logs/run.txt` 和 `output/vuln.json`。

## 目录

```text
agent.py                         入口
react_agent/                     Agent 主逻辑
ghidra_scripts/export_analysis.py Ghidra headless 导出脚本
prompts/system_prompt.txt         ReAct 规则和工具协议
targets/challenge                 待分析 ELF，需自行放入
logs/run.txt                      运行后生成
output/vuln.json                  运行后生成
requirements.txt                  Python 依赖
```

## 输入

需要准备：

```text
targets/challenge
radare2 可执行文件
Ghidra analyzeHeadless 可执行文件
OPENAI_API_KEY
```

## 安装

```bash
cd 6.6-react-agent
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 配置

可以用环境变量：

```bash
export OPENAI_API_KEY="..."
export OPENAI_MODEL="gpt-4.1-mini"
export R2_PATH="/opt/homebrew/bin/r2"
export JAVA_HOME="/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home"
export GHIDRA_HEADLESS="/path/to/ghidra/support/analyzeHeadless"
```

也可以复制一份 `.env`，程序会自动读取：

```bash
cp .env.example .env
```

然后编辑 `.env`，把 `OPENAI_API_KEY=put-your-key-here` 改成自己的 Key。`.env` 已被 `.gitignore` 忽略，不会提交。

如果 `radare2`、Java 和 Ghidra 已在 PATH 或通过上述环境变量配置好，`python agent.py --check` 会显示它们是否可用。

也可以运行时传参数：

```bash
python agent.py \
  --target targets/challenge \
  --r2-path /opt/homebrew/bin/r2 \
  --java-home "/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home" \
  --ghidra-headless "/path/to/ghidra/support/analyzeHeadless" \
  --model gpt-4.1-mini
```

## 先检查环境

```bash
python agent.py --check
```

它只检查路径和配置，不会调用 LLM，也不会跑 r2/Ghidra。

## 正式运行

```bash
python agent.py
```

运行成功后会生成：

```text
logs/run.txt
output/vuln.json
```

`logs/run.txt` 会记录完整 ReAct 过程，包括 `Thought`、`Action`、`Observation` 和最终 `Final Answer`。Agent 代码会强制要求最终答案前至少调用过一次 `r2` 和一次 `Ghidra`。

`output/vuln.json` 固定格式：

```json
{
  "vuln_type": "stack_buffer_overflow",
  "location": "main or 0x401234",
  "cause": "Untrusted input reaches a fixed-size stack buffer through scanf without a width limit."
}
```

## 工作流

```text
1. agent.py 读取目标文件、Prompt 和模型配置
2. LLM 输出 Thought + Action JSON
3. Agent 解析 Action
4. 如果是 r2，就执行只读 r2 命令
5. 如果是 Ghidra，就用 analyzeHeadless 静态分析并导出反编译结果
6. 工具输出作为 Observation 写入 logs/run.txt
7. Observation 继续喂给 LLM
8. LLM 证据足够后输出 Final JSON
9. Agent 把 Final JSON 原样写入 output/vuln.json
```

## 注意

- 不要提交 API Key。
- `targets/challenge` 如果课程要求提交，按老师要求处理；否则不要误提交无关二进制。
- 如果 Ghidra 路径不在 PATH，必须设置 `GHIDRA_HEADLESS` 或传 `--ghidra-headless`。
- 如果系统 `java` 不可用，必须设置 `JAVA_HOME` 或传 `--java-home`。
- Ghidra 第一次分析会比较慢，结果会缓存在 `.cache/ghidra/`。
- 如果把 Ghidra 本体或 zip 包临时放在 `tools/`，该目录已被 `.gitignore` 忽略，不会误提交。
