<?php

// Expire the authentication cookie
unset($_SESSION['authenticated']); 
setcookie('authenticated', '', time() - 3600, '/');

// Expire the Administrator cookie
unset($_SESSION['isSiteAdministrator']); 
setcookie('isSiteAdministrator', '', time() - 3600, '/');
// Redirect to the login page
header('Location: /login.php');
exit();

?>