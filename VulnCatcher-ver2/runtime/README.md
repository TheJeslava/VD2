# lite 靶场部署说明

## 1. 目录

```
VulnCatcher-ver2/runtime/
├─ benchmark-lite/            # 从 BenchmarkJavaRetry 复制并裁剪为 66 个样本
│  ├─ src/main/java/.../testcode/          # 66 个 servlet
│  ├─ src/main/webapp/<category>-00/       # 66 个 HTML
│  ├─ src/main/resources/                  # ESAPI/context/hibernate/...
│  ├─ src/config/                          # Tomcat web.xml/server.xml 模板
│  ├─ .keystore
│  └─ target/benchmark.war                 # 构建产物（41 MB）
├─ build_lite_targets.py    # 生成 66 条 URL/通道清单
├─ lite-targets.json        # URL 实验清单（66 条）
├─ run_experiments.py       # 66 例实验驱动（4 workers）
└─ metrics.py               # 指标统计
```

## 2. 裁剪

从 `../BenchmarkJavaRetry` 复制完整工程，然后：

1. 用 `lite/src/main/java/.../testcode` 的 66 个文件替换 `src/main/java/.../testcode`；
2. 删除 webapp 下全部 `*-0*` 类别目录，只放回 66 个样本 HTML；
3. 保留 `WEB-INF`、`js`、`css`、`img`、`META-INF`、`src/config`、`src/main/resources`、`.keystore`。

这样保留了完整 Benchmark 的构建/部署能力，只把样本数裁到 66。

## 3. 构建

`benchmark-lite/pom.xml` 做了两处运行环境适配（仅 runtime 副本）：

- 移除 `spotless-maven-plugin` 的 `apply` execution：它要求 git 仓库/`origin/master`，裁剪副本里不满足；
- 清空 `tomcat.jvmargs.debug`：避免 `-Djava.compiler=NONE` + JDWP 让 Tomcat 部署极慢。

```powershell
cd VulnCatcher-ver2\runtime\benchmark-lite
docker run --rm -v "${PWD}:/workspace" -v sunset-m2:/root/.m2 -w /workspace `
  docker.m.daocloud.io/library/maven:3.9-eclipse-temurin-17 `
  mvn -B -DskipTests package
```

产物：`target/benchmark.war`。

## 4. 运行容器

使用 Tomcat 9 + JDK 17 镜像，WAR 复制到容器本地（避免 Windows bind mount 上 41 MB WAR 的注解扫描过慢）。

```powershell
# 1) 创建容器：先解包 WAR 启动 HSQLDB/LDAP，再启动 Tomcat
docker create --name sunset-benchmark -p 8080:8080 `
  docker.m.daocloud.io/library/tomcat:9-jdk17-temurin `
  bash -lc 'set -e; mkdir -p /tmp/bench; cd /tmp/bench; jar xf /usr/local/tomcat/webapps/benchmark.war; CP="/tmp/bench/WEB-INF/classes:/tmp/bench/WEB-INF/lib/*"; mkdir -p /tmp/db; java -cp "$CP" org.hsqldb.Server --database.0 file:/tmp/db/benchmark.db --dbname.0 benchmarkDataBase >/tmp/hsqldb.log 2>&1 & java -cp "$CP" org.owasp.benchmark.helpers.LDAPServer >/tmp/ldap.log 2>&1 & sleep 6; exec catalina.sh run'

# 2) 放入 WAR 和带 JNDI Resource 的 server.xml
docker cp .\benchmark-lite\target\benchmark.war sunset-benchmark:/usr/local/tomcat/webapps/benchmark.war
docker cp .\tomcat-server.xml sunset-benchmark:/usr/local/tomcat/conf/server.xml

# 3) 启动
docker start sunset-benchmark
```

`tomcat-server.xml` 是在 Tomcat 默认 `conf/server.xml` 的 `<GlobalNamingResources>` 中加入：

```xml
<Resource name="jdbc/ApplicationContext_BenchmarkDB" auth="Container"
  type="javax.sql.DataSource" username="sa" password=""
  driverClassName="org.hsqldb.jdbc.JDBCDriver"
  url="jdbc:hsqldb:hsql://localhost/benchmarkDataBase;file:benchmark.db;sql.enforce_size=false;shutdown=false;"
  maxTotal="12" maxIdle="2" maxWaitMillis="5000" removeAbandonedOnBorrow="true" />
```

`WEB-INF/META-INF/context.xml` 里的 `ResourceLink` 会把它映射为 `jdbc/BenchmarkDB`，`DataBaseFilter`/`DatabaseHelper` 才能初始化表。

## 5. 验证

```powershell
curl.exe -sS -o NUL -w "%{http_code}`n" http://localhost:8080/benchmark/
curl.exe -sS -i -X POST http://localhost:8080/benchmark/pathtraver-00/BenchmarkTest00002 `
  -H "Cookie: BenchmarkTest00002=FileName"
```

正常应返回 `200` 和 `Now ready to write to file: ...`。  
若返回 500 且日志提示 `jdbc/ApplicationContext_BenchmarkDB not bound`，检查 `server.xml` 的 GlobalNamingResources 是否已复制；若提示 `Connection refused`，检查 HSQLDB 9001 是否先于第一次请求启动。

## 6. 说明

- 靶场用 HTTP 8080。Benchmark 的部分 cookie 设置了 `Secure`，浏览器在 HTTP 下不会回传；本地 AWVS-compatible 探针/VulnCatcher-Verify显式构造 Cookie，所以实验不受影响。
- 若要接真实 AWVS，建议改成 HTTPS 8443（工程自带 `.keystore` 和 `src/config/remote/server.xml`），并让扫描器忽略自签名证书。
- 容器名 `sunset-benchmark`；删除它会丢失容器内的 DB/LDAP 进程，需按上面步骤重建。
