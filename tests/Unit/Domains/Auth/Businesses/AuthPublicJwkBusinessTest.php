<?php

namespace App\Domains\Auth\Businesses;

use Mockery;
use PHPUnit\Framework\TestCase;

class AuthPublicJwkBusinessTest extends TestCase
{
    /**
     * @covers \App\Domains\Auth\Businesses\AuthPublicJwkBusiness::process
     */
    public function testProcess()
    {
        $context = 'app-test';
        $config = [
            'app-test' => [
                'publicFilePath' => 'app-test.pub',
            ],
        ];

        $pubContent = '
            -----BEGIN PUBLIC KEY-----
            ...
            -----END PUBLIC KEY-----
        ';

        $expected = [
            "keys" => [
                [
                    "kty" => "RSA",
                    "n" => "YQ",
                    "e" => "Yg",
                ]
            ]
        ];

        $authPublicJwkBusiness = Mockery::mock(AuthPublicJwkBusiness::class)->makePartial();
        $authPublicJwkBusiness->shouldReceive('getConfig')
            ->with('token')
            ->andReturn($config)
            ->shouldReceive('getConfig')
            ->with('app')
            ->andReturn(['secretsFolder' => './secrets/'])
            ->shouldReceive('getFileContent')
            ->with('./secrets/' . 'app-test.pub')
            ->andReturn($pubContent)
            ->shouldReceive('getOpenSslDetails')
            ->with($pubContent)
            ->andReturn([
                'rsa' => [
                    'e' => 'b',
                    'n' => 'a',
                ]
            ]);

        $jwk = $authPublicJwkBusiness->process($context);
        $this->assertEquals($jwk, $expected);
    }

    /**
     * @covers \App\Domains\Auth\Businesses\AuthPublicJwkBusiness::process
     */
    public function testProcessNotFoundConfig()
    {
        $context = 'app-test';
        $config = [
            'app-test' => [],
        ];

        $authPublicJwkBusiness = Mockery::mock(AuthPublicJwkBusiness::class)->makePartial();

        $authPublicJwkBusiness->shouldReceive('getConfig')
            ->with('token')
            ->andReturn($config);

        $this->expectExceptionObject(new \Exception('Invalid credentials', 401));
        $authPublicJwkBusiness->process($context);
    }

    /**
     * @covers \App\Domains\Auth\Businesses\AuthPublicJwkBusiness::process
     */
    public function testProcessEmptyPem()
    {
        $context = 'app-test';
        $config = [
            'app-test' => [
                'publicFilePath' => 'app-test.pub',
            ],
        ];

        $pubContent = '';

        $authPublicJwkBusiness = Mockery::mock(AuthPublicJwkBusiness::class)->makePartial();
        $authPublicJwkBusiness->shouldReceive('getConfig')
            ->with('token')
            ->andReturn($config)
            ->shouldReceive('getConfig')
            ->with('app')
            ->andReturn(['secretsFolder' => './secrets/'])
            ->shouldReceive('getFileContent')
            ->with('./secrets/' . 'app-test.pub')
            ->andReturn($pubContent);

        $this->expectExceptionObject(new \Exception('Failed to get jwk details', 404));
        $authPublicJwkBusiness->process($context);
    }

    protected function tearDown(): void
    {
        Mockery::close();
    }
}
