# Security

*By [salliyme]*

This library helps you generate RSA cert and encrypt and decrypt simply.

## Installation

Use [Composer](https://getcomposer.org/) to install the library.

``` bash
$ composer require salliyme/security
```

## Basic usage

```php
use salliyme\security\Encrypt;

$instance = new Encrypt();
$instance->generateKey();
$instance->init();
$plainData = "This is a test Encrypt Encrypt and Decrypt Methods.";
$enc = $instance->private_encrypt($plainData);
$dec = $instance->public_decrypt($enc);
echo "Text:", $dec, PHP_EOL;
$plainText = "This data to test Encrypt public Encrypt and private Decrypt.";
$enc1 = $instance->public_encrypt($plainText);
$dec1 = $instance->private_decrypt($enc1);
echo "Text2:", $dec1, PHP_EOL;
```

## License

This bundle is under the MIT license. For the full copyright and license
information please view the LICENSE file that was distributed with this source code.
