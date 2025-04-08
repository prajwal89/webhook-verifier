<?php

namespace Tests\WebhookVerifier;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Prajwal89\WebhookVerifier\Exceptions\SignatureException;
use Prajwal89\WebhookVerifier\Exceptions\TimestampException;
use Prajwal89\WebhookVerifier\WebhookVerifier;

class WebhookVerifierTest extends TestCase
{
    private const TEST_SECRET = "whsec_MfKQ9r4OrbVlYAKE4QxSvsCUQvxgwauQ";
    private const TEST_RAW_SECRET = "test_raw_secret_key";

    public function testConstructor()
    {
        $verifier = new WebhookVerifier(self::TEST_SECRET);
        $this->assertInstanceOf(WebhookVerifier::class, $verifier);
    }

    public function testFromRaw()
    {
        $verifier = WebhookVerifier::fromRaw(self::TEST_RAW_SECRET);
        $this->assertInstanceOf(WebhookVerifier::class, $verifier);
    }

    public function testVerifyMissingHeaders()
    {
        $verifier = new WebhookVerifier(self::TEST_SECRET);
        $payload = json_encode(['event' => 'test']);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage("Missing required webhook headers");

        $verifier->verify($payload, []);
    }

    public function testVerifyInvalidTimestamp()
    {
        $verifier = new WebhookVerifier(self::TEST_SECRET);
        $payload = json_encode(['event' => 'test']);
        $headers = [
            'webhook-id' => 'test-id',
            'webhook-timestamp' => 'invalid',
            'webhook-signature' => 'v1,signature'
        ];

        $this->expectException(TimestampException::class);

        $verifier->verify($payload, $headers);
    }

    public function testVerifyExpiredTimestamp()
    {
        $verifier = new WebhookVerifier(self::TEST_SECRET);
        $payload = json_encode(['event' => 'test']);
        $headers = [
            'webhook-id' => 'test-id',
            'webhook-timestamp' => (string)(time() - 3600), // 1 hour ago
            'webhook-signature' => 'v1,signature'
        ];

        $this->expectException(TimestampException::class);
        $this->expectExceptionMessage("Message timestamp too old");

        $verifier->verify($payload, $headers);
    }

    public function testVerifyFutureTimestamp()
    {
        $verifier = new WebhookVerifier(self::TEST_SECRET);
        $payload = json_encode(['event' => 'test']);
        $headers = [
            'webhook-id' => 'test-id',
            'webhook-timestamp' => (string)(time() + 3600), // 1 hour in future
            'webhook-signature' => 'v1,signature'
        ];

        $this->expectException(TimestampException::class);
        $this->expectExceptionMessage("Message timestamp too new");

        $verifier->verify($payload, $headers);
    }

    public function testVerifyInvalidSignature()
    {
        $verifier = new WebhookVerifier(self::TEST_SECRET);
        $payload = json_encode(['event' => 'test']);
        $headers = [
            'webhook-id' => 'test-id',
            'webhook-timestamp' => (string)time(),
            'webhook-signature' => 'v1,invalid_signature'
        ];

        $this->expectException(SignatureException::class);
        $this->expectExceptionMessage("No matching signature found");

        $verifier->verify($payload, $headers);
    }

    public function testVerifyValidSignature()
    {
        // Create a custom verifier with a known secret for testing
        $secret = 'test_secret';
        $verifier = WebhookVerifier::fromRaw($secret);

        $msgId = 'test-webhook-id';
        $timestamp = time();
        $payload = json_encode(['event' => 'test_event']);

        // Generate a valid signature
        $signature = $verifier->sign($msgId, $timestamp, $payload);

        $headers = [
            'webhook-id' => $msgId,
            'webhook-timestamp' => (string)$timestamp,
            'webhook-signature' => $signature
        ];

        // Verify should succeed and return the decoded payload
        $result = $verifier->verify($payload, $headers);

        $this->assertEquals(['event' => 'test_event'], $result);
    }

    public function testMultipleSignatures()
    {
        // Create a custom verifier with a known secret for testing
        $secret = 'test_secret';
        $verifier = WebhookVerifier::fromRaw($secret);

        $msgId = 'test-webhook-id';
        $timestamp = time();
        $payload = json_encode(['event' => 'test_event']);

        // Generate a valid signature
        $signature = $verifier->sign($msgId, $timestamp, $payload);

        $headers = [
            'webhook-id' => $msgId,
            'webhook-timestamp' => (string)$timestamp,
            'webhook-signature' => "v2,invalid_sig " . $signature
        ];

        // Verify should succeed and return the decoded payload
        $result = $verifier->verify($payload, $headers);

        $this->assertEquals(['event' => 'test_event'], $result);
    }
}
