# Standard Webhooks PHP Verifier

A PHP implementation of the [Standard Webhooks](https://github.com/standard-webhooks/standard-webhooks) signature verification.

## Installation

You can install the package via composer:

```bash
composer require prajwal89/webhook-verifier
```

## Usage

### Basic Usage

```php
<?php

require 'vendor/autoload.php';

use StandardWebhooks\WebhookVerifier;
use StandardWebhooks\Exceptions\WebhookVerificationException;

$secret = 'whsec_MfKQ9r4OrVlYAKE4QxSvsCUQvxgwauQ'; // Your webhook secret
$verifier = new WebhookVerifier($secret);

// Get the request headers
$headers = [
    'webhook-id' => $_SERVER['HTTP_WEBHOOK_ID'],
    'webhook-timestamp' => $_SERVER['HTTP_WEBHOOK_TIMESTAMP'],
    'webhook-signature' => $_SERVER['HTTP_WEBHOOK_SIGNATURE'],
];

// Get the raw request payload
$payload = file_get_contents('php://input');

try {
    // Verify the signature and get the decoded data
    $data = $verifier->verify($payload, $headers);
    
    // Process the verified webhook data
    handleWebhook($data);
    
    http_response_code(200);
    echo json_encode(['success' => true]);
} catch (WebhookVerificationException $e) {
    // Handle verification failure
    http_response_code(401);
    echo json_encode(['error' => $e->getMessage()]);
}

function handleWebhook($data) {
    // Process your webhook data here
    // $eventType = $data['event'];
    // ...
}
```

## Exception Handling

The package provides three exception types:

1. `WebhookVerificationException` - Base exception class for all webhook verification errors
2. `SignatureException` - Thrown when there's an issue with the signature
3. `TimestampException` - Thrown when there's an issue with the timestamp

You can catch these exceptions separately if you need specific error handling:

```php
try {
    $data = $verifier->verify($payload, $headers);
    // Process webhook
} catch (TimestampException $e) {
    // Handle timestamp issues (e.g., expired webhook)
    echo "Timestamp error: " . $e->getMessage();
} catch (SignatureException $e) {
    // Handle signature issues (e.g., tampered payload)
    echo "Signature error: " . $e->getMessage();
} catch (WebhookVerificationException $e) {
    // Handle other verification issues
    echo "Verification error: " . $e->getMessage();
}
```

## Security

The package uses constant-time comparison to prevent timing attacks when verifying signatures.

The default tolerance for timestamp verification is 5 minutes (300 seconds) to account for minor time differences between servers.

## Testing

```bash
composer test
```

## License

The MIT License (MIT). Please see [License File](https://github.com/prajwal89/webhook-verifier/blob/main/LICENCE) for more information.