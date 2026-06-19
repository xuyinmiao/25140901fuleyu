# Semgrep 实验：仅自写规则扫描报告

## 1. 人工源码分析

### 1.1 通读范围

通读本仓库中与会话/注册/查询相关的模块：`app.py`（Web 与请求入口）、`db.py`（SQLite 访问与查询构造）、`utils.py`（密码与令牌辅助）。

### 1.2 选定的缺陷类

**以「用户可控或外界影响的字符串，经非参数化 SQL 拼接到 `execute`」为核心的 SQL 注入/不安全查询构造类问题。**

人工在 `db.py` 可见 **三处**坏模式：`%` 格式化、f-string、`.format` 拼 SQL 后 `cur.execute(query)`。本实验**仅**对其中 **`%` 格式化** 编写 **一条** Semgrep 规则（见 `sqli_dynamic_execute.yaml`）。

### 1.3 为何适合用 Semgrep 表达（针对本条规则）

- **两跳结构**「`$Q = "..." % ...` → … → `execute($Q)`」在函数体内可用 `pattern` 块稳定刻画；
- 不依赖污点引擎即可在小型仓库中回归。

### 1.4 「合适触发」判据（本条规则）

1. 存在 `query = "…%s…" % 变量`（或等价 `%` 拼接）将值拼入 SQL 字符串的赋值。
2. 同函数体内随后出现 `cur.execute(该变量)`，且**不是** `execute(sql, 元组)` 参数化形式。
3. 当 1 中变量在工程内来自 `request` 等路径时，与「不可信数据进 SQL」的人工判断一致；规则不单独声称「已证明可利用」。

---

## 2. 自写规则与测试

- **规则文件**：`semgrep-lab/rules/sqli_dynamic_execute.yaml`（**仅** `id: sqli-exec-after-modulo-format`）
- **规则测试**：`semgrep-lab/rules/sqli_dynamic_execute.test.py`

---

## 3. 扫描方式（仅自写规则）

```bash
semgrep --config semgrep-lab/rules/sqli_dynamic_execute.yaml .
```

```bash
semgrep --test semgrep-lab/rules --metrics=off
```

**运行输出**：`semgrep-lab/output/semgrep.txt`

---

## 4. 结论（仅基于自写规则扫描结果）

- **命中位置（业务代码）**：`db.py` 中 **`find_user`**（`% username` 后 `cur.execute(query)`）与本条规则一致；**不命中** f-string 的 `find_user_by_email` 与 **`.format`** 的 `create_user`（本实验未为这两种形态写规则）。
- **与人工分析是否一致**：对 **`find_user` 这一处** 的静态刻画与人工一致；对另两处，**仅人工分析**已覆盖，**自动化扫描**未覆盖（有意的规则范围选择）。
- **漏报（至少一句）**：所有未使用 `%` 拼 SQL 再 `execute(变量)` 的同类问题（如 f-string、`.format`、或跨函数包装）本条规则**均不报告**。
- **误报（至少一句）**：若 `%` 拼接的仅来自**受信任/固定**源、形态与判据 1+2 相同，仍可能报警，需结合判据 3 人工排除。

---

## 5. 提交流程清单

| 项 | 路径/说明 |
|----|-----------|
| 分析流程图 | `semgrep-lab/analysis-flowchart.md` |
| 自写规则 + 测试 | `semgrep-lab/rules/sqli_dynamic_execute.yaml`、`sqli_dynamic_execute.test.py` |
| Semgrep 输出 | `semgrep-lab/output/semgrep.txt` |
| 主报告 | 仓库根目录 `付乐宇-25140901-Semgrep实验.md` |
