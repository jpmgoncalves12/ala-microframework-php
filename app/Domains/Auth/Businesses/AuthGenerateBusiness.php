<?php

namespace App\Domains\Auth\Businesses;

use App\Businesses\BaseBusiness;
use App\Exceptions\Custom\InvalidCredentialsException;
use JwtManager\JwtManager;

class AuthGenerateBusiness extends BaseBusiness
{
    /**
     * process the request with business rules
     * @param array $data
     * @param string $type
     * @throws InvalidCredentialsException
     * @return array
     */
    public function process(
        array $data,
        string $subject = 'api'
    ): array {
        if ($this->getConfig('app')['shouldUsePemToSignJWT']) {
            $authConfig = $this->getConfigFromContext($data['context']);
            if (empty($authConfig)) {
                throw new InvalidCredentialsException('Invalid credentials', 401);
            }
    
            return $this->generatePemToken(
                $data['context'],
                $subject,
                $authConfig['pemFileName']
            );
        }

        $auth = $this->getFromToken(
            $data['token'],
            $data['secret']
        );

        if (empty($auth)) {
            throw new InvalidCredentialsException('Invalid credentials', 401);
        }

        return $this->generateToken(
            $auth['name'],
            $subject
        );
    }

    /**
     * generate token
     * @param string $audience
     * @param string $subject
     * @return array
     */
    public function generateToken(
        string $audience,
        string $subject
    ): array {
        $jwt = $this->newJwtToken(
            config('app.jwt_app_secret'),
            $audience
        );

        $jwtToken = $jwt->generate($audience, $subject);
        $validate = date('Y-m-d H:i:s', time() + $jwt->getExpire());

        return [
            'token' => $jwtToken,
            'valid_until' => $validate,
        ];
    }

    /**
     * generate token
     * @param string $audience
     * @param string $subject
     * @param string $pemFileName
     * @return array
     */
    public function generatePemToken(
        string $context,
        string $subject,
        string $pemFileName
    ): array {
        $privateKey = file_get_contents($this->getConfig('app')['secretsFolder'] . $pemFileName);
        $jwt = $this->newJwtToken(
            $privateKey,
            $context,
            900,
            300,
            true
        );

        $jwtToken = $jwt->generate(
            $context,
            $subject
        );

        $validate = date(
            'Y-m-d H:i:s',
            time() + $jwt->getExpire()
        );

        return [
            'token' => $jwtToken,
            'valid_until' => $validate,
        ];
    }

    /**
     * search on config for token and secret to authenticate
     * @param string $token
     * @param string $secret
     * @return array|null
     */
    public function getFromToken(
        string $token,
        string $secret
    ): ?array {
        $tokens = $this->getConfig('token.data');
        $hasSecret = $tokens[$token]['secret'] ?? null;

        if ($secret == $hasSecret) {
            return $tokens[$token];
        }

        return null;
    }

    /**
     * search on config for token and secret to authenticate
     * @param string $token
     * @param string $secret
     * @return array|null
     */
    public function getConfigFromContext(
        string $context
    ): array {
        $tokens = $this->getConfig('token');
        $config = $tokens[$context] ?? [];

        if (!empty($config)) {
            return $config;
        }

        return [];
    }

    /**
     * @codeCoverageIgnore
     * create and return jwt helper
     * @param string $context
     * @return JwtManager
     */
    public function newJwtToken(
        string $appSecret,
        string $context,
        int $expire = 900,
        int $renew = 300,
        bool $useCertificate = false
    ): JwtManager {
        return new JwtManager(
            $appSecret,
            $context,
            $expire,
            $renew,
            $useCertificate
        );
    }
}
