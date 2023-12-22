<?php

namespace App\Domains\Auth\Businesses;

use App\Businesses\BaseBusiness;
use App\Exceptions\Custom\InvalidCredentialsException;

class AuthPublicJwkBusiness extends BaseBusiness
{
    /**
     * process the request with business rules
     * @param array $data
     * @param string $type
     * @throws InvalidCredentialsException
     * @return array
     */
    public function process(
        string $context
    ): array {
        $pemsArray = $this->getConfig('token');
        if (
            empty($pemsArray[$context]) ||
            empty($pemsArray[$context]['pemFileName'])
        ) {
            throw new InvalidCredentialsException('Invalid credentials', 401);
        }

        $pemFileName = $pemsArray[$context]['pemFileName'];
        $privateKey = file_get_contents($this->getConfig('app')['secretsFolder'] . $pemFileName);
        if (empty($privateKey)) {
            throw new InvalidCredentialsException('Invalid credentials', 401);
        }

        $keyInfo = openssl_pkey_get_details(openssl_pkey_get_public($privateKey));
        $jwk = [
            'keys' => [
                [
                    'kty' => 'RSA',
                    'n' => rtrim(str_replace(['+', '/'], ['-', '_'], base64_encode($keyInfo['rsa']['n'])), '='),
                    'e' => rtrim(str_replace(['+', '/'], ['-', '_'], base64_encode($keyInfo['rsa']['e'])), '='),
                ],
            ],
        ];

        return $jwk;
    }
}
