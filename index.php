<!DOCTYPE html>
<html>
<head>
    <title>Encrypt/Decrypt Message</title>
</head>
<body>
    <h2>Encrypt/Decrypt Message</h2>
    <form method="post" action="">
        <label for="key">Key:</label><br>
        <input type="text" id="key" name="key" required><br><br>

        <label for="message">Message to Encrypt:</label><br>
        <textarea id="message" name="message"></textarea><br><br>

        <label for="encrypted_message">Message to Decrypt:</label><br>
        <textarea id="encrypted_message" name="encrypted_message"></textarea><br><br>

        <input type="submit" name="action" value="Encrypt">
        <input type="submit" name="action" value="Decrypt">
    </form>

    <?php
    function encrypt_message($key, $message) {
        // Generate a random salt
        $salt = openssl_random_pseudo_bytes(16);

        // Derive a key from the key using PBKDF2
        $key = hash_pbkdf2("sha256", $key, $salt, 100000, 32, true);

        // Generate a random IV
        $iv = openssl_random_pseudo_bytes(16);

        // Encrypt the message
        $ciphertext = openssl_encrypt($message, 'aes-256-cfb', $key, OPENSSL_RAW_DATA, $iv);

        // Encode the salt, IV, and ciphertext
        return base64_encode($salt . $iv . $ciphertext);
    }

    function decrypt_message($key, $encrypted_message) {
        // Decode the encrypted message
        $encrypted_message = base64_decode($encrypted_message);

        // Extract the salt, IV, and ciphertext
        $salt = substr($encrypted_message, 0, 16);
        $iv = substr($encrypted_message, 16, 16);
        $ciphertext = substr($encrypted_message, 32);

        // Derive the key from the key using PBKDF2
        $key = hash_pbkdf2("sha256", $key, $salt, 100000, 32, true);

        // Decrypt the message
        return openssl_decrypt($ciphertext, 'aes-256-cfb', $key, OPENSSL_RAW_DATA, $iv);
    }

    if ($_SERVER["REQUEST_METHOD"] == "POST") {
        $key = $_POST['key'];

        if ($_POST['action'] == 'Encrypt' && !empty($_POST['message'])) {
            $message = $_POST['message'];
            $encrypted_message = encrypt_message($key, $message);
            echo "<h3>Encrypted Message:</h3>";
            echo "<p>$encrypted_message</p>";
        } elseif ($_POST['action'] == 'Decrypt' && !empty($_POST['encrypted_message'])) {
            $encrypted_message = $_POST['encrypted_message'];
            $decrypted_message = decrypt_message($key, $encrypted_message);
            echo "<h3>Decrypted Message:</h3>";
            echo "<p>$decrypted_message</p>";
        } else {
            echo "<p>Please provide the appropriate input for the selected action.</p>";
        }
    }
    ?>
</body>
</html>
