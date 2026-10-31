# 静态证据

- 文件: 046.php
- 行号: 11
- 片段:
```
	$_SESSION['last_session_id_high']++;
	$cookie_value = md5($_SESSION['last_session_id_high']);
	setcookie("dvwaSession", $cookie_value, time()+3600, "/vulnerabilities/weak_id/", $_SERVER['HTTP_HOST'], false, false);
```
