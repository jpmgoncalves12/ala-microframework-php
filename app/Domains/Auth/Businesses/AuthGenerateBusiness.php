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
        $authConfig = $this->getConfigFromContext($data['context']);
        if (empty($authConfig)) {
            throw new InvalidCredentialsException('Invalid credentials', 401);
        }

        return $this->generateToken(
            $data['context'],
            $subject,
            $authConfig['pemFileName']
        );
    }

    /**
     * generate token
     * @param string $audience
     * @param string $subject
     * @return array
     */
    public function generateToken(
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
