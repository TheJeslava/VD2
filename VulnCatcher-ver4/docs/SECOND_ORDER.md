# 4-2 二次注入专属挖掘与验证（SecondOrderAnalyzer）

## 1. 定义

二次注入（second-order injection）不是「输入立刻进入 sink」，而是：

```
请求 A：攻击者输入 → 被持久化（DB / Session / Cache / 文件）
请求 B：从存储读出 → 在另一个上下文拼接 → 危险汇点
```

它绕过第一阶段的净化，因为第一阶段与第二阶段的**上下文不同**：
- 第一阶段按「用户输入」转义；
- 第二阶段按「可信数据库值」使用，往往不再校验；
- 存储层不区分代码与数据。

---

## 2. 三要素

| 要素 | 例子 | 代码信号 |
|---|---|---|
| 存储写点 | `INSERT INTO orders(name) VALUES ('" + name + "')` | `INSERT/UPDATE/REPLACE/MERGE`、`setAttribute`、`cache.set/put` |
| 存储读点 | `String stored = queryForObject("SELECT name FROM orders ...")` | `SELECT ... FROM` 赋值、`getAttribute`、`cache.get` |
| 读取后的危险汇点 | `queryForList("... name = '" + stored + "'")` | SQL/命令/模板/路径/HTML 拼接 |

只有三者同时存在，SecondOrderAnalyzer 才产出链。

---

## 3. 算法（`sunset/second_order.py`）

```
1. 对每个源码文件：
   a. 收集污点变量（请求参数/头/Cookie/Spring 注解）
   b. 扫描持久化写点，记录 (storage, key, line, source)
   c. 扫描存储读点，记录 (storage, key, var, line)

2. 全局按 key 关联：
   - SQL: sql:<table>
   - Session: session:<attribute>
   - Cache: cache:<key>
   - File: file:last

3. 对每个读点：
   - 找同 key 的写点（同文件优先取读点之前最近；否则跨文件）
   - 在读点之后 60 行内找 sink
   - sink 必须出现「读出的变量」且存在拼接/格式化迹象
   - 如果 sink 是参数化/绑定（? / setString），跳过

4. 组装 chain：
   store → read → sink
   并生成两阶段 POC
```

### 3.1 存储写点示例

```java
@PostMapping("/create")
public void create(@RequestParam String name) {
    jdbc.update("INSERT INTO orders(name) VALUES ('" + name + "')");
}
```

- 污点：`@RequestParam String name`
- 写点：`INSERT INTO orders`
- key：`sql:orders`

### 3.2 存储读点示例

```java
@GetMapping("/search")
public Object search() {
    String stored = jdbc.queryForObject("SELECT name FROM orders WHERE id=1", String.class);
    return jdbc.queryForList("SELECT * FROM orders WHERE name='" + stored + "'");
}
```

- 读点：`SELECT name FROM orders` → `stored`
- 汇点：`queryForList` 字符串拼接
- key 匹配：`sql:orders`

---

## 4. 静态验证（不是动态验证）

SecondOrderAnalyzer 的「验证」是**证据闭环检查**，不是执行 POC：

| obligation | 含义 | 实现 |
|---|---|---|
| `store_reachable` | 写点有可识别端点 | `_endpoint_for` |
| `storage_roundtrip` | 读点与写点同 table/key | `persist_by_key` |
| `read_to_sink` | 读出的变量进入 sink | `_find_sinks` |
| `sanitizer_gap` | sink 未参数化/白名单 | `?`/`setString` 跳过 |
| `context_gap` | 第一阶段净化不覆盖第二阶段 | 报告中说明 |
| `poc_replay_plan` | 两阶段 POC 文本 | `_poc_plan` |
| `dynamic_executed` | 永远 false | `safety` |

报告 `second_order.json` 与 finding 的 `verification_notes` 会明确写：
「静态验证：store→read→sink 三要素齐全；未执行两阶段 POC。」

---

## 5. 两阶段 POC

`poc_store.sh`：

```sh
#!/usr/bin/env sh
set -eu
curl -sS -X POST 'http://TARGET:8080/orders/create' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'name=x%27%20OR%20%271%27%3D%271%27%20--%20SUNSET2O'
```

`poc_trigger.sh`：

```sh
#!/usr/bin/env sh
set -eu
curl -sS -X GET 'http://TARGET:8080/orders/search'
```

`poc_all.sh` 顺序执行两者。预期：第二次响应出现全量数据、SQL 报错或异常业务结果。

POC 安全标记：

```json
{
  "executed": false,
  "network_egress": false,
  "requires_authorization": true,
  "target_uses_placeholder": true
}
```

---

## 6. 支持的存储类型

| 类型 | 写点 | 读点 | key |
|---|---|---|---|
| SQL | `INSERT/UPDATE/REPLACE/MERGE` | `SELECT ... FROM` 赋值 | `sql:<table>` |
| Session | `setAttribute("k", v)` | `getAttribute("k")` | `session:<k>` |
| Cache | `redis.set("k", v)` / `cache.put("k", v)` | `redis.get("k")` | `cache:<k>` |
| File | `Files.write` / `file_put_contents` | `Files.read*` / `open` | `file:last`（粗粒度） |

文件类型是粗粒度关联；建议人工确认路径是否一致。

---

## 7. 误报与限制

- **同表不同业务**：同一张表可能有多个写点/读点，key 只到 table 级，可能跨业务误关联。报告中会给出 store/read/sink 行号，需人工确认。
- **ORM 隐式 SQL**：`repository.save` + `findBy...` 可能不出现 `INSERT/SELECT` 字面量，当前规则不一定能识别。
- **跨服务**：写点与读点在不同服务/不同数据库实例时，本管线无法确认共享存储。
- **净化**：如果第二阶段确实做了参数化/白名单，`_find_sinks` 会跳过 `?`/`setString`；但自定义净化函数可能识别不到。
- **文件类型**：`file:last` 只适合单文件示例，生产代码建议扩展为路径哈希 key。

---

## 8. Fixture 走读

`tests/fixtures/second_order/OrderController.java`：

| 行 | 代码 | 角色 |
|---|---|---|
| 22 | `public void create(@RequestParam String name)` | 污点源 |
| 23 | `INSERT INTO orders(name) VALUES ('" + name + "')` | 写点 |
| 27 | `public ... search(@RequestParam String q)` | 读点所在端点 |
| 28 | `SELECT name FROM orders WHERE id = 1` → `stored` | 读点 |
| 29 | `queryForList("... name = '" + stored + "'")` | sink |

运行：

```powershell
python -m unittest tests.test_pipeline.TestSecondOrder -v
```

断言：
- `chains[0].storage == "sql"`
- `chains[0].storage_key == "sql:orders"`
- POC 包含 `poc_store.sh` / `poc_trigger.sh`
- `poc_all.sh` 包含 `/orders/create` 与 `/orders/search`
- `safety.executed == False`

---

## 9. 与 AutoCVE 的差异

AutoCVE 的 finding 流程以「一次 source→sink」为主，二次注入没有独立阶段。VulnCatcher把二次注入提升为一等公民：

- 独立 agent（SecondOrderAnalyzer）；
- 独立数据模型（`SecondOrderChain`）；
- 独立报告（`second_order.json`）；
- 独立 POC（两阶段）；
- 独立验证义务（store/read/sink + sanitizer gap）。

这也是「逻辑更简单」的一部分：不是把所有逻辑塞进一个大 agent，而是把二次注入拆成可解释的三步。
