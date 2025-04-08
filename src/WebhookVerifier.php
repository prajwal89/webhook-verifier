<?php

declare(strict_types=1);

namespace Prajwal89\WebhookVerifier;

use InvalidArgumentException;
use Prajwal89\WebhookVerifier\Exceptions\SignatureException;
use Prajwal89\WebhookVerifier\Exceptions\TimestampException;

/**
 * Webhook Verifier for Standard Webhooks Implementation
 *
 * @see https://github.com/standard-webhooks/standard-webhooks
 */
class WebhookVerifier
{
    private const SECRET_PREFIX = 'whsec_';

    /**
     * Time Tolerance in seconds for webhook timestamp verification
     */
    private const TOLERANCE = 300; // 5 minutes (5 * 60 seconds)

    /**
     * Constructor
     *
     * @param  string  $secret  The webhook secret key
     * @param  int  $tolerance  Tolerance in seconds
     */
    public function __construct(
        private string $secret,
        private int $tolerance = self::TOLERANCE
    ) {
        if (substr($secret, 0, strlen(self::SECRET_PREFIX)) === self::SECRET_PREFIX) {
            $secret = substr($secret, strlen(self::SECRET_PREFIX));
        }

        $this->secret = base64_decode($secret);
    }

    /**
     * Create a verifier with a raw (already decoded) secret
     *
     * @param  string  $secret  Raw secret string
     */
    public static function fromRaw(string $secret): self
    {
        $obj = new self('');
        $obj->secret = $secret;

        return $obj;
    }

    /**
     * Verify a webhook payload against its signature
     *
     * @param  string  $payload  The webhook payload (JSON string)
     * @param  array  $headers  The webhook headers
     * @return array The decoded payload if verification succeeds
     *
     * @throws WebhookVerificationException If verification fails
     */
    public function verify(string $payload, array $headers): array
    {
        if (
            !isset($headers['webhook-id']) ||
            !isset($headers['webhook-timestamp']) ||
            !isset($headers['webhook-signature'])
        ) {
            throw new InvalidArgumentException('Missing required webhook headers');
        }

        $msgId = $headers['webhook-id'];
        $msgTimestamp = $headers['webhook-timestamp'];
        $msgSignature = $headers['webhook-signature'];

        $timestamp = $this->verifyTimestamp($msgTimestamp);

        $signature = $this->sign($msgId, $timestamp, $payload);
        $expectedSignature = explode(',', $signature, 2)[1];

        $passedSignatures = explode(' ', $msgSignature);
        foreach ($passedSignatures as $versionedSignature) {
            $sigParts = explode(',', $versionedSignature, 2);

            if (count($sigParts) !== 2) {
                continue; // Skip malformed signatures
            }

            $version = $sigParts[0];
            $passedSignature = $sigParts[1];

            if (strcmp($version, 'v1') !== 0) {
                continue; // Skip unknown versions
            }

            if (hash_equals($expectedSignature, $passedSignature)) {
                return json_decode($payload, true);
            }
        }

        throw new SignatureException('No matching signature found');
    }

    /**
     * Sign a message with the webhook secret
     *
     * @param  string  $msgId  The webhook ID
     * @param  int  $timestamp  The webhook timestamp
     * @param  string  $payload  The webhook payload
     * @return string The signature
     *
     * @throws SignatureException If signature generation fails
     */
    public function sign(string $msgId, int $timestamp, string $payload): string
    {
        if (!$this->isPositiveInteger($timestamp)) {
            throw new SignatureException('Invalid timestamp');
        }

        $toSign = "{$msgId}.{$timestamp}.{$payload}";
        $hex_hash = hash_hmac('sha256', $toSign, $this->secret);
        $signature = base64_encode(pack('H*', $hex_hash));

        return "v1,{$signature}";
    }

    /**
     * Verify the timestamp is within tolerance
     *
     * @param  string  $timestampHeader  The timestamp from headers
     * @return int The verified timestamp
     *
     * @throws TimestampException If timestamp is invalid or outside tolerance
     */
    private function verifyTimestamp(string $timestampHeader): int
    {
        $now = time();

        try {
            $timestamp = intval($timestampHeader, 10);
        } catch (\Exception $e) {
            throw new TimestampException('Invalid timestamp format');
        }

        if ($timestamp < ($now - self::TOLERANCE)) {
            throw new TimestampException('Message timestamp too old');
        }

        if ($timestamp > ($now + self::TOLERANCE)) {
            throw new TimestampException('Message timestamp too new');
        }

        return $timestamp;
    }

    /**
     * Check if a value is a positive integer
     *
     * @param  mixed  $v  The value to check
     * @return bool True if value is a positive integer
     */
    private function isPositiveInteger($v): bool
    {
        return is_numeric($v) && !is_float($v + 0) && (int) $v === $v && (int) $v > 0;
    }
}
