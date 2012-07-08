<?php

require 'unicorn.php';

$unicorn = new Unicorn(array(
	'appId'	=> '90',
	'secret' => 'DpHtaNaXPGfMeWLwGFPXog((',
	'key' => 'JmaI0jaKMDDknDcGnEdzCQ((',
));

$user = $unicorn->getUser();

if ($user) {
  try {
    // Proceed knowing you have a logged in user who's authenticated.
	  $user_profile = $unicorn->api('/me?site=stackoverflow');
  } catch (UnicornApiException $e) {
    error_log($e);
    $user = null;
  }
}

// Login or logout url will be needed depending on current user state.
if ($user) {
  // $logoutUrl = $unicorn->getLogoutUrl();
} else {
   $loginUrl = $unicorn->getLoginUrl();
}

?>

<!doctype html>
<html>
  <head>
    <title>php-sdk</title>
  </head>
  <body>

    <?php if ($user): ?>
       <span>Logged In</span>
    <?php else: ?>
      <div>
        Login using OAuth 2.0 handled by the PHP SDK:
        <a href="<?php echo $loginUrl; ?>">Login with Stack Exchange</a>
      </div>
    <?php endif ?>
<h3>PHP Session</h3>
    <pre><?php print_r($_SESSION); ?></pre>
	<?php if ($user): ?>
      <h3>You</h3>
      <img src=<?php echo $user_profile['items'][0]['profile_image']; ?>>

      <h3>Your User Object (/me)</h3>
      <pre><?php print_r($user_profile); ?></pre>
    <?php else: ?>
      <strong><em>You are not Connected.</em></strong>
    <?php endif ?>
</body>
</html>
