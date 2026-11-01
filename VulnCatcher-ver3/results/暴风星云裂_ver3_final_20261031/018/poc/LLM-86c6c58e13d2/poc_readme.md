# 静态证据

- 文件: 018.php
- 行号: 32
- 片段:
```
function decrypt ($ciphertext, $key) {
	$e = openssl_decrypt($ciphertext, 'aes-128-ecb', $key, OPENSSL_PKCS1_PADDING);
	if ($e === false) {
		throw new Exception ("Decryption failed");
	}
	return $e;
}

$key = "ik ben een aardbei";

$errors = "";
$success = "";
$messages = "";

if ($_SERVER['REQUEST_METHOD'] == "POST") {
	try {
		if (!array_key_exists ('token', $_POST)) {
			throw new Exception ("No token passed");
		} else {
			$token = $_POST['token'];
			if (strlen($token) % 32 != 0) {
				throw new Exception ("Token is in wrong format");
			} else {
				$decrypted = decrypt(hex2bin ($token), $key);

				$user = json_decode ($decrypted);
				if ($user === null) {
					throw new Exception ("Could not decode JSON object.");
				}

				if ($user->user == "sweep" && $user->ex > time() && $user->level == "admin") {
```
