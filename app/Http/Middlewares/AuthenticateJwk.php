<?php

namespace App\Http\Middlewares;

use App\Exceptions\Custom\InvalidCredentialsException;
use Closure;
use Exception;
use JwtManager\JwtManager;

class AuthenticateJwk
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

        $jwt = $this->getJwtToken($context);
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
     * @param string $context
     * @throws InvalidCredentialsException
     * @return JwtManager
     */
    public function getJwtToken(
        string $context
    ): JwtManager {
        $privateFilePath = $this->getConfig('token')[$context]['privateFilePath'];
        if (empty($privateFilePath)) {
            throw new InvalidCredentialsException('Invalid jwk Context', 401);
        }

        $secretFolder = $this->getConfig('app')['secretsFolder'];
        $pemContent = $this->getPemContent($secretFolder . $privateFilePath);
        return $this->newJwtToken(
            $pemContent,
            $context,
            900,
            300,
            true
        );
    }

    /**
     * @codeCoverageIgnore
     * @param string $path
     * @return bool|string
     */
    public function getPemContent(
        string $path
    ): string|false {
        return file_get_contents($path);
    }

    /**
     * @codeCoverageIgnore
     * create and return jwt helper
     * @param string $context
     * @return JwtManager
     */
    public function newJwtToken(
        string $privateKey,
        string $context
    ): JwtManager {
        return new JwtManager(
            $privateKey,
            $context
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
