<?php

session_start();

include './components/loggly-logger.php';

$hostname = 'backend-mysql-database';
$username = getenv('MYSQL_USER');
$password = getenv('MYSQL_PASSWORD');
$database = getenv('MYSQL_DATABASE');

$max_attempts = 4;
$lockout_time = 5 * 60; 

if (!isset($_SESSION['login_attempts'])) {
    $_SESSION['login_attempts'] = 0;
}
if (!isset($_SESSION['login_locked_until'])) {
    $_SESSION['login_locked_until'] = 0;
}



$conn = new mysqli($hostname, $username, $password, $database);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

unset($error_message);

if ($conn->connect_error) {
    $errorMessage = "Connection failed: " . $conn->connect_error;    
    die($errorMessage);
}

// Check if the form is submitted
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    $stmt = $conn->prepare("SELECT * FROM users WHERE username = ? AND password = ? AND approved = 1 LIMIT 1");
    $stmt->bind_param("ss", $username, $password);
    $stmt->execute();

    $result = $stmt->get_result();

    #$sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password' AND approved = 1";
   # $result = $conn->query($sql);

    if($result->num_rows > 0 && time() >= $_SESSION['login_locked_until']) {
       
        $userFromDB = $result->fetch_assoc();

        //$_COOKIE['authenticated'] = $username;
        $_SESSION['authenticated'] = $username;     

       if ($userFromDB['default_role_id'] == 1)
        {        
            setcookie('isSiteAdministrator', true, time() + 3600, '/');                
            $_SESSION['isSiteAdministrator'] = true;
        }else{
            unset($_COOKIE['isSiteAdministrator']); 
            setcookie('isSiteAdministrator', '', -1, '/'); 
            $_SESSION['isSiteAdministrator'] = false;
        }
        header("Location: index.php");
        $logger->info("Login successful for username: $username");
        exit();
    } else {
        $_SESSION['login_attempts']++;
        $error_message = 'Invalid username or password. Attempt #' . $_SESSION['login_attempts'];
        $logger->warning("Login failed for username: $username");  

        if ($_SESSION['login_attempts'] >= $max_attempts) {
        $_SESSION['login_locked_until'] = time() + $lockout_time;
        $error_message = "Too many failed attempts. Try again later.";
        $logger->warning("User $username potentially attempting a bruteforce attack.");
        }
        else if (time() < $_SESSION['login_locked_until']) {
            $error_message = "Account is temporarily locked. Try again later.";
        }
    }

    $conn->close();
}

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css">
    <title>Login Page</title>
</head>
<body>
    <div class="container mt-5">
        <div class="col-md-6 offset-md-3">
            <h2 class="text-center">Login</h2>
            <?php if (isset($error_message)) : ?>
                <div class="alert alert-danger" role="alert">
                    <?php echo $error_message; ?>
                </div>
            <?php endif; ?>
            <form action="login.php" method="post">
                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" class="form-control" id="username" name="username" required>
                </div>
                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="password" class="form-control" id="password" name="password" required>
                </div>
                <button type="submit" class="btn btn-primary btn-block">Login</button>
            </form>
            <div class="mt-3 text-center">
                <a href="./users/request_account.php" class="btn btn-secondary btn-block">Request an Account</a>
            </div>
        </div>
    </div>
</body>
</html>
