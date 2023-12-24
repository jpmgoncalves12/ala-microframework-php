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
        if ($this->getConfig('app')['usePemToSignJWT']) {
            $tokens = $this->getConfig('token');
            $config = $tokens[$data['context']] ?? [];
            if (empty($config)) {
                throw new InvalidCredentialsException('Invalid credentials', 401);
            }

            return $this->generatePemToken(
                $data['context'],
                $subject,
                $config['privateFilePath']
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
            $this->getConfig('app')['jwt_app_secret'],
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
     * @param string $privateFilePath
     * @return array
     */
    public function generatePemToken(
        string $context,
        string $subject,
        string $privateFilePath
    ): array {
        $privateKey = $this->getPemContent(
            $this->getConfig('app')['secretsFolder'] . $privateFilePath
        );

        $jwt = $this->newJwtToken(
            $privateKey,
            $context
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
     * @codeCoverageIgnore
     * @param string $path
     * @return bool|string
     */
    public function getPemContent(
        string $path
    ) {
        return file_get_contents($path);
    }

    /**
     * @codeCoverageIgnore
     * create and return jwt helper
     * @param string $context
     * @return JwtManager
     */
    public function newJwtToken(
        string $appSecret,
        string $context
    ): JwtManager {
        return new JwtManager(
            $appSecret,
            $context
        );
    }
}
