<?php declare(strict_types=1);
/*
 * This file is part of the WebPush library.
 *
 * (c) Louis Lagrange <lagrange.louis@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Minishlink\WebPush\ContentEncoding;
use Minishlink\WebPush\Utils;
use Minishlink\WebPush\VAPID;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\TestWith;

#[CoversClass(VAPID::class)]
final class VAPIDTest extends PHPUnit\Framework\TestCase
{
    public static function vapidProvider(): array
    {
        return [
            [
                'http://push.com',
                [
                    'subject' => 'https://test.com',
                    'publicKey' => 'BA6jvk34k6YjElHQ6S0oZwmrsqHdCNajxcod6KJnI77Dagikfb--O_kYXcR2eflRz6l3PcI2r8fPCH3BElLQHDk',
                    'privateKey' => '-3CdhFOqjzixgAbUSa0Zv9zi-dwDVmWO7672aBxSFPQ',
                ],
                ContentEncoding::aesgcm,
                1475452165,
                'WebPush eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwOi8vcHVzaC5jb20iLCJleHAiOjE0NzU0NTIxNjUsInN1YiI6Imh0dHBzOi8vdGVzdC5jb20ifQ.JFr6qZp7_1tXtAbkdEFjZtGYAeAyQvQPOJQu7FQcbuvA2JwHsb65YlMUOFPG2qGImaESrHdO-G7blkUP5XHOYw',
                'p256ecdsa=BA6jvk34k6YjElHQ6S0oZwmrsqHdCNajxcod6KJnI77Dagikfb--O_kYXcR2eflRz6l3PcI2r8fPCH3BElLQHDk',
            ], [
                'http://push.com',
                [
                    'subject' => 'https://test.com',
                    'publicKey' => 'BA6jvk34k6YjElHQ6S0oZwmrsqHdCNajxcod6KJnI77Dagikfb--O_kYXcR2eflRz6l3PcI2r8fPCH3BElLQHDk',
                    'privateKey' => '-3CdhFOqjzixgAbUSa0Zv9zi-dwDVmWO7672aBxSFPQ',
                ],
                ContentEncoding::aes128gcm,
                1475452165,
                'vapid t=eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwOi8vcHVzaC5jb20iLCJleHAiOjE0NzU0NTIxNjUsInN1YiI6Imh0dHBzOi8vdGVzdC5jb20ifQ.kXXd2JaK1583Le1mheFKEKSF1I4rYFKvF0HKNXO8et-w2UYSc3d0pbsbN_sP17PvcsO_zT8XJZ-gbKWlCOGksw, k=BA6jvk34k6YjElHQ6S0oZwmrsqHdCNajxcod6KJnI77Dagikfb--O_kYXcR2eflRz6l3PcI2r8fPCH3BElLQHDk',
                null,
            ],
        ];
    }

    /**
     * @throws ErrorException
     */
    #[dataProvider('vapidProvider')]
    public function testGetVapidHeaders(string $audience, array $vapid, ContentEncoding $contentEncoding, int $expiration, string $expectedAuthorization, ?string $expectedCryptoKey): void
    {
        $vapid = VAPID::validate($vapid);
        $headers = VAPID::getVapidHeaders(
            $audience,
            $vapid['subject'],
            $vapid['publicKey'],
            $vapid['privateKey'],
            $contentEncoding,
            $expiration
        );

        $this->assertArrayHasKey('Authorization', $headers);
        $this->assertEquals(Utils::safeStrlen($expectedAuthorization), Utils::safeStrlen($headers['Authorization']));
        $this->assertEquals($this->explodeAuthorization($expectedAuthorization), $this->explodeAuthorization($headers['Authorization']));

        if ($expectedCryptoKey) {
            $this->assertArrayHasKey('Crypto-Key', $headers);
            $this->assertEquals($expectedCryptoKey, $headers['Crypto-Key']);
        } else {
            $this->assertArrayNotHasKey('Crypto-Key', $headers);
        }
    }

    private function explodeAuthorization(string $auth): array
    {
        $auth = explode('.', $auth);
        array_pop($auth); // delete the signature which changes each time
        return $auth;
    }

    public function testCreateVapidKeys(): void
    {
        $keys = VAPID::createVapidKeys();
        $this->assertArrayHasKey('publicKey', $keys);
        $this->assertArrayHasKey('privateKey', $keys);
        $this->assertGreaterThanOrEqual(86, strlen($keys['publicKey']));
        $this->assertGreaterThanOrEqual(42, strlen($keys['privateKey']));
    }

    #[TestWith([[]])]
    #[TestWith([['subject' => '']])]
    #[TestWith([['subject' => 'test']])]
    #[TestWith([['subject' => 'mailto:']])]
    #[TestWith([['subject' => 'mailto:localhost']])]
    #[TestWith([['subject' => 'https://']])]
    #[TestWith([['subject' => 'https://example.com', 'pemFile' => '']])]
    #[TestWith([['subject' => 'https://example.com', 'pemFile' => 'abc.pem']])]
    #[TestWith([['subject' => 'https://example.com', 'pem' => '']])]
    #[TestWith([['subject' => 'https://example.com', 'publicKey' => '']])]
    public function testValidateException(array $vapid): void
    {
        $this->expectException(Exception::class);
        VAPID::validate($vapid);
    }
}
