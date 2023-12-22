<?php

namespace App\Domains\Auth\Businesses;

use JwtManager\JwtManager;
use Mockery;
use PHPUnit\Framework\TestCase;

class AuthGenerateBusinessTest extends TestCase
{
    /**
     * @covers \App\Domains\Auth\Businesses\AuthGenerateBusiness::process
     */
    public function testProcessAndNotFoundConfig()
    {
        $data = [
            'token' => 'token',
            'secret' => 'secret',
        ];

        $authGenerateBusiness = Mockery::mock(AuthGenerateBusiness::class)->makePartial();
        $authGenerateBusiness->shouldReceive('getFromToken')
            ->with('token', 'secret')
            ->andReturn(null)
            ->shouldReceive('generateToken')
            ->never()
            ->andReturn(null);

        $this->expectExceptionObject(new \Exception('Invalid credentials', 401));

        $authGenerateBusiness->process($data);
    }

    /**
     * @covers \App\Domains\Auth\Businesses\AuthGenerateBusiness::process
     */
    public function testProcess()
    {
        $now = date('Y-m-d H:i:s', time() + 900);

        $data = [
            'token' => 'token',
            'secret' => 'secret',
        ];

        $response = [
            'token' => 'token',
            'valid_until' => $now
        ];

        $authGenerateBusiness = Mockery::mock(AuthGenerateBusiness::class)->makePartial();
        $authGenerateBusiness->shouldReceive('getFromToken')
            ->with('token', 'secret')
            ->andReturn([
                'name' => 'Test'
            ])
            ->shouldReceive('generateToken')
            ->once()
            ->with('Test', 'api')
            ->andReturn($response);

        $business = $authGenerateBusiness->process($data);

        $this->assertEquals($response, $business);
    }

    /**
     * @covers \App\Domains\Auth\Businesses\AuthGenerateBusiness::process
     */
    public function testProcessWithPem()
    {
        $now = date('Y-m-d H:i:s', time() + 900);

        $data = [
            'context' => 'app-test',
        ];

        $config = [
            'app-test' => [
                'pemFileName' => 'app-test.pem'
            ]
        ];

        $response = [
            'token' => 'token',
            'valid_until' => $now
        ];

        $authGenerateBusiness = Mockery::mock(AuthGenerateBusiness::class)->makePartial();
        $authGenerateBusiness->shouldReceive('getConfig')
            ->with('app')
            ->andReturn(['shouldUsePemToSignJWT' => 1])
            ->shouldReceive('getConfig')
            ->with('token')
            ->andReturn($config)
            ->shouldReceive('generatePemToken')
            ->with(
                $data['context'],
                'api',
                $config[$data['context']]['pemFileName']
            )
            ->andReturn($response);

        $business = $authGenerateBusiness->process($data);

        $this->assertEquals($response, $business);
    }

    /**
     * @covers \App\Domains\Auth\Businesses\AuthGenerateBusiness::process
     */
    public function testProcessWithNotFoundPem()
    {
        $data = [
            'context' => 'app-test',
        ];

        $authGenerateBusiness = Mockery::mock(AuthGenerateBusiness::class)->makePartial();
        $authGenerateBusiness->shouldReceive('getConfig')
            ->with('app')
            ->andReturn(['shouldUsePemToSignJWT' => 1])
            ->shouldReceive('getConfig')
            ->with('token')
            ->andReturn([]);

        $this->expectExceptionObject(new \Exception('Invalid credentials', 401));

        $authGenerateBusiness->process($data);
    }

    /**
     * @covers \App\Domains\Auth\Businesses\AuthGenerateBusiness::generateToken
     */
    public function testGenerateToken()
    {
        $audience = 'audience';
        $subject = 'subject';

        $secret = 'secret';

        $token = 'token';
        $expire = 900;

        $authGenerateBusiness = Mockery::mock(AuthGenerateBusiness::class)->makePartial();
        $authGenerateBusiness->shouldReceive('getConfig')
            ->with('app')
            ->andReturn(['jwt_app_secret' => $secret]);

        $jwtManagerMock = Mockery::mock(JwtManager::class)
            ->shouldReceive('generate')
            ->with($audience, $subject)
            ->andReturn($token)
            ->shouldReceive('getExpire')
            ->withNoArgs()
            ->andReturn($expire)
            ->getMock();

        $authGenerateBusiness->shouldReceive('newJwtToken')
            ->with(
                $secret,
                $audience
            )
            ->andReturn($jwtManagerMock);

        $business = $authGenerateBusiness->generateToken($audience, $subject);

        $this->assertEquals($token, $business['token']);
    }

    /**
     * @covers \App\Domains\Auth\Businesses\AuthGenerateBusiness::generatePemToken
     */
    public function testGeneratePemToken()
    {
        $context = 'context';
        $subject = 'subject';

        $secretsPath = './secret/';
        $pemFileName = 'app-test.pem';

        $pemContent = '
            -----BEGIN PRIVATE KEY-----
            ...
            -----END PRIVATE KEY-----
        ';

        $token = 'token';
        $expire = 900;

        $authGenerateBusiness = Mockery::mock(AuthGenerateBusiness::class)->makePartial();
        $authGenerateBusiness->shouldReceive('getConfig')
            ->with('app')
            ->andReturn(['secretsFolder' => $secretsPath])
            ->shouldReceive('getPemContent')
            ->with($secretsPath . $pemFileName)
            ->andReturn($pemContent);

        $jwtManagerMock = Mockery::mock(JwtManager::class)
            ->shouldReceive('generate')
            ->with($context, $subject)
            ->andReturn($token)
            ->shouldReceive('getExpire')
            ->withNoArgs()
            ->andReturn($expire)
            ->getMock();

        $authGenerateBusiness->shouldReceive('newJwtToken')
            ->with(
                $pemContent,
                $context,
                900,
                300,
                true
            )
            ->andReturn($jwtManagerMock);

        $business = $authGenerateBusiness->generatePemToken(
            $context,
            $subject,
            $pemFileName
        );

        $this->assertEquals($token, $business['token']);
    }

    /**
     * @covers \App\Domains\Auth\Businesses\AuthGenerateBusiness::getFromToken
     */
    public function testGenerateTokenAndNotHasConfig()
    {
        $authGenerateBusiness = Mockery::mock(AuthGenerateBusiness::class)->makePartial();
        $authGenerateBusiness->shouldReceive('getConfig')
            ->with('tokens.data')
            ->andReturn(null);

        $business = $authGenerateBusiness->getFromToken('token', 'secret');

        $this->assertNull($business);
    }

    /**
     * @covers \App\Domains\Auth\Businesses\AuthGenerateBusiness::getFromToken
     */
    public function testGenerateTokenAndHasConfig()
    {
        $token = [
            'hash_test' => [
                'name' => 'test-front',
                'secret' => 'secret',
            ],
        ];

        $authGenerateBusiness = Mockery::mock(AuthGenerateBusiness::class)->makePartial();
        $authGenerateBusiness->shouldReceive('getConfig')
            ->with('token.data')
            ->andReturn($token);

        $business = $authGenerateBusiness->getFromToken('hash_test', 'secret');

        $this->assertEquals($token['hash_test'], $business);
    }

    /**
     * @covers \App\Domains\Auth\Businesses\AuthGenerateBusiness::getFromToken
     */
    public function testGenerateTokenAndWrongSecret()
    {
        $token = [
            'hash_test' => [
                'name' => 'test-front',
                'secret' => 'secret2',
            ],
        ];

        $authGenerateBusiness = Mockery::mock(AuthGenerateBusiness::class)->makePartial();
        $authGenerateBusiness->shouldReceive('getConfig')
            ->with('tokens.data')
            ->andReturn($token);

        $business = $authGenerateBusiness->getFromToken('hash_test', 'secret');

        $this->assertNull($business);
    }

    protected function tearDown(): void
    {
        Mockery::close();
    }
}
