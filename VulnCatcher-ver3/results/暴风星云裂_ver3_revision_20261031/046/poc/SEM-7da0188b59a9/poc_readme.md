# 静态证据

- 文件: 046.php
- 行号: 10
- 片段:
```
9: 	$_SESSION['last_session_id_high']++;
10: 	$cookie_value = md5($_SESSION['last_session_id_high']);
11: 	setcookie("dvwaSession", $cookie_value, time()+3600, "/vulnerabilities/weak_id/", $_SERVER['HTTP_HOST'], false, false);
```
