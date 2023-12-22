<?php

namespace App\Http\Middlewares;

use App\Exceptions\Custom\InvalidCredentialsException;
use Closure;
use Exception;
use JwtManager\JwtManager;

class AuthenticateJwt
{
    /**
     * handle an incoming request,
     *   authenticating with jwt token
     * @param Request $request
     * @param Closure $next
     * @throws InvalidCredentialsException
     * @return void
     */
    public function handle(
        $request,
        Closure $next
    ) {
        $token = $request->headers->get('Authorization') ?? null;
        $context = $request->headers->get('Context') ?? null;

        if (empty($token) || empty($context)) {
            throw new InvalidCredentialsException('Missing authorization', 401);
        }

        $token = str_replace('Bearer ', '', $token);

        $pemFileName = $this->getConfig('token')[$context]['pemFileName'];
        if (empty($pemFileName)) {
            throw new InvalidCredentialsException('Invalid jwk Context', 401);
        }

        $privateKey = file_get_contents($this->getConfig('app')['secretsFolder'] . $pemFileName);

        $jwt = $this->newJwtToken(
            $privateKey,
            $context,
            900,
            300,
            true
        );

        try {
            $jwt->isValid($token);
            $jwt->isOnTime($token);
        } catch (Exception $exception) {
            throw new InvalidCredentialsException(
                'Invalid token or expired token',
                401
            );
        }

        $data = $jwt->decodePayload($token);
        $audience = $data['aud'];
        $subject = $data['sub'];

        if ($subject !== 'api') {
            throw new InvalidCredentialsException('Invalid subject', 401);
        }

        if ($context !== $audience) {
            throw new InvalidCredentialsException('Invalid context', 401);
        }

        $exp = $data['exp'];
        $validUntil = date('Y-m-d H:i:s', $exp);

        $needRefresh = $jwt->tokenNeedToRefresh($token);
        if ($needRefresh) {
            $token = $jwt->generate($audience, $subject);
            $validUntil = date('Y-m-d H:i:s', time() + 900);
        }

        $request->jwtToken = [
            'token' => $token,
            'valid_until' => $validUntil,
        ];

        $request->info = config('version.info');

        return $next($request);
    }

    /**
     * @codeCoverageIgnore
     * create and return jwt helper
     * @param string $context
     * @return JwtManager
     */
    public function newJwtToken(
        string $privateKey,
        string $context,
        int $expire = 900,
        int $renew = 300,
        bool $useCertificate = false
    ): JwtManager {
        return new JwtManager(
            $privateKey,
            $context,
            $expire,
            $renew,
            $useCertificate
        );
    }

    /**
     * @codeCoverageIgnore
     * get laravel config
     * @param string $config
     * @return array|null
     */
    public function getConfig(
        string $config
    ): ?array {
        return config($config);
    }
}
