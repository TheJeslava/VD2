# 静态证据

- 文件: 018.php
- 行号: 3
- 片段:
```
2: function decrypt ($ciphertext, $key) {
3: 	$e = openssl_decrypt($ciphertext, 'aes-128-ecb', $key, OPENSSL_PKCS1_PADDING);
4: 	if ($e === false) {
```
