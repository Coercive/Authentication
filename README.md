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
$ObjectAuthentification = new Authentification();

# EXAMPLE PASS
$password = '1234hello_world';

# HASH
$hash = $ObjectAuthentification->hash($password);

# VERIFY
if($ObjectAuthentification->verify($password, $hash)) {
    # Do something
}

# NEED UPDATE REHASH ?
if($ObjectAuthentification->needsRehash($hash)) {
    # Do something
}

```
