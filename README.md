Coercive Authentification Security
==================================

Use PHP password hash system.

Get
---
```
composer require coercive/authentification
```

Usage
-----
```php
use Coercive\Security\Authentification\Authentification;
$auth = new Authentification;

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

```
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

With de default parameters,
for testing 1 million of pasword possibility,
you will need :
1000000 * 1,5 (average) / 60 (minutes) / 60 (hours) / 24 (days)
=> more than 17 days of waiting !