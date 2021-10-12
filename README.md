Coercive Authentication Security
================================

Use PHP password hash system.

Get
---
```
composer require coercive/authentication
```

Usage
-----
```php
use Coercive\Security\Authentication\Authentication;
$auth = new Authentication;

# EXAMPLE PASS
$password = '1234hello_world';

# HASH
$hash = $auth->hash($password);

# VERIFY
if($auth->verify($password, $hash)) {
    # Access granted
}
else {
    # Access denied
}

# NEED UPDATE REHASH ?
if($auth->needsRehash($hash)) {
    # Do something
}
```

Debounce
--------

You can debounce miswriting password for prevent bruteforce attack.
The debounce is random for cover the tracks.

```php
# Set your min/max randow debounce
$auth->debounce(500, 1500);

# VERIFY
if($auth->verify($password, $hash)) {
    # Access granted
}
else {
    # Access denied
    # In this case you will wait for 500-1500 milliseconds
}
```

RateLimit
---------

You can count the number of passages of any element (connections, visits, API calls ...) during a given period, and decide if the passage is authorized.

With the default settings, it is possible to add an additional timeout (sleep) before proceeding to the next step.

```php
use Coercive\Security\Authentication\RateLimit;

$ip = $_SERVER['REMOTE_ADDR'];
$dir = '/mycustomdirectory/ratelimit';

# Example for 200 requests by hours
$ratelimit = new RateLimit($dir, 200, 3600);

# Example of waiting duration (for isAllowed method)
$ratelimit->debounce(5000000);

# You can add a global IP or pass it to >set(...) >get(...) methods
$ratelimit->setIp($ip);

# Add passage to stack
$ratelimit->set();

# Get current allowed passages quantity
$ratelimit->get();

# Return true/false if current passage is allowed
$allowed = $ratelimit->isAllowed();
echo $allowed ? 'Allowed' : 'Unallowed';

# When use isAllowed, you can also retrieve the last passages quantity
$i = $ratelimit->lastNb();
if($i >= 180) {
    echo 'The maximum limit is soon reached.';
}
```

StopForumSpam
-------------

PHP handler use API Stop Forum Spam [https://www.stopforumspam.com].

You can check if an IP, email, or username appears in spamlist.

Please see API usage here [https://www.stopforumspam.com/usage].

```php
use Coercive\Security\Authentication\StopForumSpam;

$sfspam = new StopForumSpam;

try {
    # Check if the given email is in spamlist
    if($sfspam->checkEmail('example@email.com')) {
        # Do something
    }
    # Check if the given email (MD5 encode) is in spamlist
    if($sfspam->checkEmail('example@email.com', true)) {
        # Do something
    }
    # Check if the given IP is in spamlist
    if($sfspam->checkIp('1.1.1.1')) {
        # Do something
    }
    # Check if the given user name is in spamlist
    if($sfspam->checkUserName('John Doe')) {
        # Do something
    }
}
catch (Exception $e) {
    # The check can throw an exception when can't call API or API send failed status.
}
```

You can add some callbacks to automate action after the checks.

```php
use Coercive\Security\Authentication\StopForumSpam;

$sfspam = new StopForumSpam;

# Global callback is used before each check
$sfspam->setCallbackBefore(function ($type, $value) {

    # Do something...
    if($type === StopForumSpam::TYPE_EMAIL && $value === 'test@email.com') {
        echo 'hello world';
    }

    # Return not-null => stop processing and force return boolean casted value of your return
    return true;
    return false;
    
    # No return or return null => continue processing
    return null;
});
# Global callback is used after each check
$sfspam->setCallbackAfter(function ($type, $status, $value) {
    echo $value;
    if($type === StopForumSpam::TYPE_EMAIL && $status) {
        exit;
    }

    # Return not-null => override api status and force return boolean casted value of your return
    return true;
    return false;

    # No return or return null => return api status
    return null;
});

# You can override value when pass a parameter as a reference
$sfspam->setCallbackBefore(function ($type, &$value) {
    $value = 'new value';
});

# You have also specific callback for each type
$sfspam->setCallbackBeforeEmail(function ($email) {});
$sfspam->setCallbackAfterEmail(function ($status, $email) {});
$sfspam->setCallbackBeforeIp(function ($ip) {});
$sfspam->setCallbackAfterIp(function ($status, $ip) {});
$sfspam->setCallbackBeforeIp(function ($name) {});
$sfspam->setCallbackAfterUserName(function ($status, $name) {});
```