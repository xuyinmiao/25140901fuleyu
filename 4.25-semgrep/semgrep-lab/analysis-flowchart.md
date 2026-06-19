# 源码级分析流程图（实验提交用）

下图描述：从**不可信输入**到**人工判据**、再映射到**本实验唯一一条** Semgrep 规则的关系；扫描阶段仅使用 `semgrep-lab/rules/sqli_dynamic_execute.yaml` 中自写规则，不使用任何现成规则包。

```mermaid
flowchart TB
  subgraph in["不可信/外部影响输入"]
    A1["`GET /users?q=`（用户名查询）"]
    A2["`GET /users?email=`（按邮箱查）"]
    A3["`POST /register`（注册字段）"]
  end

  subgraph flow["数据流与汇聚点（人工阅读）"]
    B1["`app.py` 将 `request` 中字符串传入 `db` 各函数"]
    B2["`db.py` 中至少 `find_user` 使用 `%` 将值拼进 SQL"]
    B3["`cur.execute(完整拼好的字符串)` 而非 `execute(sql, 元组参数）`"]
  end

  subgraph crit["人工「合适触发」判据（要点）"]
    C1["存在「SQL 由模板 + 外值」经 `%` 拼出的赋值"]
    C2["同一控制流中随后出现 **`execute(该变量)`**（非占位符+元组第二参）"]
    C3["拼入值来自**可被用户影响的参数**时与风险一致（人工）"]
  end

  subgraph rules["自写规则（本实验仅一条）"]
    R1["`sqli-exec-after-modulo-format`"]
  end

  A1 --> B1
  A2 --> B1
  A3 --> B1
  B1 --> B2 --> B3
  B2 --> C1
  B3 --> C2
  A1 --> C3
  C1 --> R1
  C2 --> R1
```

说明：`db.py` 中 **f-string / `.format`** 的同类风险由**人工阅读**标出；本实验**只**将 **`%` + `execute(变量)`** 固化为规则 `sqli-exec-after-modulo-format`，扫描因此**仅**对该语法形态报警，对另两处为**规则层面漏报**（见主报告）。
