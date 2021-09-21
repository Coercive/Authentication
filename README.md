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