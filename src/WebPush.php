<?php

declare(strict_types=1);

/*
 * This file is part of the WebPush library.
 *
 * (c) Louis Lagrange <lagrange.louis@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Minishlink\WebPush;

use Base64Url\Base64Url;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Pool;
use GuzzleHttp\Psr7\Request;
use Psr\Http\Message\ResponseInterface;

/**
 *
 * @phpstan-type AuthArray array{
 *     VAPID?: mixed
 * }
 * @phpstan-type VAPIDArray array{
 *     Authorization: string,
 *     Crypto-Key?: string
 *   }
 * @phpstan-type WebPushOptions array{
 *     TTL: int,
 *     urgency: string|null,
 *     topic: string|null,
 *     batchSize: int,
 *     requestConcurrency: int,
 *     contentType: string
 * }
 *
 * @phpstan-type WebPushOptionsInput array{
 *     TTL?: int,
 *     urgency?: string,
 *     topic?: string,
 *     batchSize?: int,
 *     requestConcurrency?: int,
 *     contentType?: string
 * }
 */
class WebPush
{
    protected Client $client;
    /**
     * @var AuthArray
     */
    protected array $auth;

    /**
     * @var list<Notification> Array of notifications.
     */
    protected array $notifications = [];

    /**
     * @var WebPushOptions Default options of the class. Used if option is not set or overridden.
     */
    public readonly array $fallbackOptions;

    /**
     * @var WebPushOptions Used as default for every push message processed.
     */
    protected array $defaultOptions;

    /**
     * @var int Automatic padding of payloads, if disabled, trade security for bandwidth
     */
    protected int $automaticPadding = Encryption::MAX_COMPATIBILITY_PAYLOAD_LENGTH;

    /**
     * @var bool Reuse VAPID headers in the same flush session to improve performance
     */
    protected bool $reuseVAPIDHeaders = false;

    /**
     * @var array<string, VAPIDArray> Dictionary for VAPID headers cache
     */
    protected array $vapidHeaders = [];

    /**
     * WebPush constructor.
     *
     * @param AuthArray                     $auth           Some servers need authentication
     * @param WebPushOptionsInput           $defaultOptions TTL, urgency, topic, batchSize, requestConcurrency
     * @param int|null                      $timeout        Timeout of POST request
     * @param array{RequestOptions?: mixed} $clientOptions
     *
     * @throws \ErrorException
     */
    public function __construct(
        array $auth = [],
        array $defaultOptions = [],
        ?int  $timeout = 30,
        array $clientOptions = []
    ) {
        Utils::checkRequirement();

        $this->fallbackOptions = [
            'TTL'                => 2419200,
            'urgency'            => null,
            'topic'              => null,
            'batchSize'          => 1000,
            'requestConcurrency' => 100,
            'contentType'        => 'application/octet-stream',
        ];

        if (isset($auth['VAPID'])) {
            $auth['VAPID'] = VAPID::validate($auth['VAPID']);
        }

        $this->auth = $auth;

        $this->setDefaultOptions($defaultOptions);

        if (!array_key_exists('timeout', $clientOptions) && isset($timeout)) {
            $clientOptions['timeout'] = $timeout;
        }
        $this->client = new Client($clientOptions);
    }

    /**
     * Queue a notification. Will be sent when flush() is called.
     *
     * @param string|null $payload If you want to send an array or object, json_encode it
     * @param WebPushOptionsInput $options Array with several options tied to this notification. If not set, will use the default options that you can set in the WebPush object
     * @param AuthArray $auth Use this auth details instead of what you provided when creating WebPush
     * @throws \ErrorException
     */
    public function queueNotification(
        SubscriptionInterface $subscription,
        ?string               $payload = null,
        array                 $options = [],
        array                 $auth = []
    ): void {
        if (isset($payload)) {
            if (Utils::safeStrlen($payload) > Encryption::MAX_PAYLOAD_LENGTH) {
                throw new \ErrorException('Size of payload must not be greater than '.Encryption::MAX_PAYLOAD_LENGTH.' octets.');
            }

            $contentEncoding = $subscription->getContentEncoding();
            if (null === $contentEncoding || '' === $contentEncoding) {
                throw new \ErrorException('Subscription should have a content encoding');
            }

            $payload = Encryption::padPayload($payload, $this->automaticPadding, ContentEncoding::from($contentEncoding));
        }

        if (array_key_exists('VAPID', $auth)) {
            $auth['VAPID'] = VAPID::validate($auth['VAPID']);
        }

        $this->notifications[] = new Notification($subscription, $payload, $options, $auth);
    }

    /**
     * @param string|null $payload If you want to send an array or object, json_encode it
     * @param WebPushOptionsInput $options Array with several options tied to this notification. If not set, will use the default options that you can set in the WebPush object
     * @param AuthArray $auth Use this auth details instead of what you provided when creating WebPush
     * @throws \ErrorException
     */
    public function sendOneNotification(
        SubscriptionInterface $subscription,
        ?string               $payload = null,
        array                 $options = [],
        array                 $auth = []
    ): MessageSentReport|null {
        $this->queueNotification($subscription, $payload, $options, $auth);
        return $this->flush()->current();
    }

    /**
     * Flush notifications. Triggers the requests.
     *
     * @param null|int $batchSize Defaults the value defined in defaultOptions during instantiation (which defaults to 1000).
     *
     * @return \Generator
     * @throws \ErrorException
     * @throws \Random\RandomException
     */
    public function flush(?int $batchSize = null): \Generator
    {
        if (0 === count($this->notifications)) {
            yield from [];
            return;
        }

        if (null === $batchSize) {
            $batchSize = $this->defaultOptions['batchSize'];
        }

        if ($batchSize < 1) {
            throw new \InvalidArgumentException('$batchSize must be positive non-zero integer.');
        }
        $batches = array_chunk($this->notifications, $batchSize);

        // reset queue
        $this->notifications = [];

        foreach ($batches as $batch) {
            // for each endpoint server type
            $requests = $this->prepare($batch);

            $promises = [];

            foreach ($requests as $request) {
                $promises[] = $this->client->sendAsync($request)
                    ->then(function ($response) use ($request) {
                        /** @var ResponseInterface $response **/
                        return new MessageSentReport($request, $response);
                    })
                    ->otherwise(fn ($reason) => $this->createRejectedReport($reason));
            }

            foreach ($promises as $promise) {
                yield $promise->wait();
            }
        }

        if ($this->reuseVAPIDHeaders) {
            $this->vapidHeaders = [];
        }
    }

    /**
     * Flush notifications. Triggers concurrent requests.
     *
     * @param callable(MessageSentReport): void $callback Callback for each notification
     * @param null|int $batchSize Defaults the value defined in defaultOptions during instantiation (which defaults to 1000).
     * @param null|int $requestConcurrency Defaults the value defined in defaultOptions during instantiation (which defaults to 100).
     */
    public function flushPooled(callable $callback, ?int $batchSize = null, ?int $requestConcurrency = null): void
    {
        if (empty($this->notifications)) {
            return;
        }

        if (null === $batchSize) {
            $batchSize = $this->defaultOptions['batchSize'];
        }

        if (null === $requestConcurrency) {
            $requestConcurrency = $this->defaultOptions['requestConcurrency'];
        }

        if ($batchSize < 1) {
            throw new \InvalidArgumentException('$batchSize must be positive non-zero integer.');
        }

        $batches = array_chunk($this->notifications, $batchSize);
        $this->notifications = [];

        foreach ($batches as $batch) {
            $batch = $this->prepare($batch);
            $pool  = new Pool(
                $this->client,
                $batch,
                [
                    'concurrency' => $requestConcurrency,
                    'fulfilled'   => function (ResponseInterface $response, int $index) use ($callback, $batch): void {
                        $request = $batch[$index];
                        $callback(new MessageSentReport($request, $response));
                    },
                    'rejected'    => function ($reason) use ($callback): void {
                        $callback($this->createRejectedReport($reason));
                    },
                ],
            );

            $promise = $pool->promise();
            $promise->wait();
        }

        if ($this->reuseVAPIDHeaders) {
            $this->vapidHeaders = [];
        }
    }

    protected function createRejectedReport(RequestException|ConnectException $reason): MessageSentReport
    {
        if ($reason instanceof RequestException) {
            $response = $reason->getResponse();
        } else {
            $response = null;
        }

        return new MessageSentReport($reason->getRequest(), $response, false, $reason->getMessage());
    }

    /**
     * @param array{Notification} $notifications
     * @return array{Request}
     *
     * @throws \ErrorException Thrown on php 8.1
     * @throws \Random\RandomException Thrown on php 8.2 and higher
     */
    protected function prepare(array $notifications): array
    {
        $requests = [];
        foreach ($notifications as $notification) {
            if (!($notification instanceof Notification)) {
                throw new \RuntimeException('$notification must be instance of Notification.');
            }
            $subscription = $notification->getSubscription();
            $endpoint = $subscription->getEndpoint();
            $userPublicKey = $subscription->getPublicKey();
            $userAuthToken = $subscription->getAuthToken();
            $contentEncoding = $subscription->getContentEncoding();
            $payload = $notification->getPayload();
            $options = $notification->getOptions($this->getDefaultOptions());
            $auth = $notification->getAuth($this->auth);

            if (!empty($payload) && !empty($userPublicKey) && !empty($userAuthToken)) {
                if (null === $contentEncoding || '' === $contentEncoding) {
                    throw new \ErrorException('Subscription should have a content encoding');
                }

                $encrypted = Encryption::encrypt($payload, $userPublicKey, $userAuthToken, ContentEncoding::from($contentEncoding));
                $cipherText = $encrypted['cipherText'];
                $salt = $encrypted['salt'];
                $localPublicKey = $encrypted['localPublicKey'];

                $headers = [
                    'Content-Type' => $options['contentType'],
                    'Content-Encoding' => $contentEncoding,
                ];

                if ($contentEncoding === ContentEncoding::aesgcm->value) {
                    $headers['Encryption'] = 'salt='.Base64Url::encode($salt);
                    $headers['Crypto-Key'] = 'dh='.Base64Url::encode($localPublicKey);
                }

                $encryptionContentCodingHeader = Encryption::getContentCodingHeader($salt, $localPublicKey, ContentEncoding::from($contentEncoding));
                $content = $encryptionContentCodingHeader.$cipherText;

                $headers['Content-Length'] = (string) Utils::safeStrlen($content);
            } else {
                $headers = [
                    'Content-Length' => '0',
                ];

                $content = '';
            }

            $headers['TTL'] = $options['TTL'];

            if (isset($options['urgency'])) {
                $headers['Urgency'] = $options['urgency'];
            }

            if (isset($options['topic'])) {
                $headers['Topic'] = $options['topic'];
            }

            if (array_key_exists('VAPID', $auth) && (null !== $contentEncoding && '' !== $contentEncoding)) {
                $audience = parse_url($endpoint, PHP_URL_SCHEME).'://'.parse_url($endpoint, PHP_URL_HOST);
                if (false === filter_var($audience, FILTER_VALIDATE_URL)) {
                    throw new \ErrorException('Audience "'.$audience.'"" could not be generated.');
                }

                $vapidHeaders = $this->getVAPIDHeaders($audience, ContentEncoding::from($contentEncoding), $auth['VAPID']);

                $headers['Authorization'] = $vapidHeaders['Authorization'];

                if (
                    $contentEncoding === ContentEncoding::aesgcm->value
                    && array_key_exists('Crypto-Key', $vapidHeaders)
                ) {
                    if (array_key_exists('Crypto-Key', $headers)) {
                        $headers['Crypto-Key'] .= ';'.$vapidHeaders['Crypto-Key'];
                    } else {
                        $headers['Crypto-Key'] = $vapidHeaders['Crypto-Key'];
                    }
                }
            }

            $requests[] = new Request('POST', $endpoint, $headers, $content);
        }

        return $requests;
    }

    public function isAutomaticPadding(): bool
    {
        return $this->automaticPadding !== 0;
    }

    public function getAutomaticPadding(): int
    {
        return $this->automaticPadding;
    }

    /**
     * @param bool|int $automaticPadding Max padding length
     *
     * @throws \ValueError
     */
    public function setAutomaticPadding(bool|int $automaticPadding): WebPush
    {
        if ($automaticPadding === true) {
            $automaticPadding = Encryption::MAX_COMPATIBILITY_PAYLOAD_LENGTH;
        } elseif ($automaticPadding === false) {
            $automaticPadding = 0;
        }

        if ($automaticPadding > Encryption::MAX_PAYLOAD_LENGTH) {
            throw new \ValueError('Automatic padding is too large. Max is '.Encryption::MAX_PAYLOAD_LENGTH.'. Recommended max is '.Encryption::MAX_COMPATIBILITY_PAYLOAD_LENGTH.' for compatibility reasons (see README).');
        }
        if ($automaticPadding < 0) {
            throw new \ValueError('Padding length should be positive or zero.');
        }

        $this->automaticPadding = $automaticPadding;

        return $this;
    }

    public function getReuseVAPIDHeaders(): bool
    {
        return $this->reuseVAPIDHeaders;
    }

    /**
     * Reuse VAPID headers in the same flush session to improve performance
     */
    public function setReuseVAPIDHeaders(bool $enabled): WebPush
    {
        $this->reuseVAPIDHeaders = $enabled;

        return $this;
    }

    /**
     * @return WebPushOptions
     */
    public function getDefaultOptions(): array
    {
        return $this->defaultOptions;
    }

    /**
     * @param WebPushOptionsInput $defaultOptions
     */
    public function setDefaultOptions(array $defaultOptions): WebPush
    {
        $this->defaultOptions['TTL'] = $defaultOptions['TTL'] ?? $this->fallbackOptions['TTL'];
        $this->defaultOptions['urgency'] = $defaultOptions['urgency'] ?? $this->fallbackOptions['urgency'];
        $this->defaultOptions['topic'] = $defaultOptions['topic'] ?? $this->fallbackOptions['topic'];
        $this->defaultOptions['batchSize'] = $defaultOptions['batchSize'] ?? $this->fallbackOptions['batchSize'];
        $this->defaultOptions['requestConcurrency'] = $defaultOptions['requestConcurrency'] ?? $this->fallbackOptions['requestConcurrency'];
        $this->defaultOptions['contentType'] = $defaultOptions['contentType'] ?? $this->fallbackOptions['contentType'];

        return $this;
    }

    public function countPendingNotifications(): int
    {
        return count($this->notifications);
    }

    /**
     * @param array{
     *     subject: string,
     *     publicKey: string,
     *     privateKey: string
     * } $vapid
     * @return VAPIDArray|null
     * @throws \ErrorException
     */
    protected function getVAPIDHeaders(string $audience, ContentEncoding $contentEncoding, array $vapid): ?array
    {
        $vapidHeaders = null;

        $cache_key = null;
        if ($this->reuseVAPIDHeaders) {
            $cache_key = implode('#', [$audience, $contentEncoding->value, crc32(serialize($vapid))]);
            if (array_key_exists($cache_key, $this->vapidHeaders)) {
                $vapidHeaders = $this->vapidHeaders[$cache_key];
            }
        }

        if (null === $vapidHeaders) {
            $vapidHeaders = VAPID::getVapidHeaders($audience, $vapid['subject'], $vapid['publicKey'], $vapid['privateKey'], $contentEncoding);
        }

        if ($this->reuseVAPIDHeaders) {
            $this->vapidHeaders[$cache_key] = $vapidHeaders;
        }

        return $vapidHeaders;
    }
}
