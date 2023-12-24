<?php

namespace App\Domains\Auth\Businesses;

use App\Businesses\BaseBusiness;
use App\Exceptions\Custom\InvalidCredentialsException;
use App\Exceptions\Custom\InvalidJwkException;

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
            empty($pemsArray[$context]['publicFilePath'])
        ) {
            throw new InvalidCredentialsException('Invalid credentials', 401);
        }

        $publicFilePath = $pemsArray[$context]['publicFilePath'];
        $publicKeyContent = $this->getFileContent(
            $this->getConfig('app')['secretsFolder'] . $publicFilePath
        );

        if (empty($publicKeyContent)) {
            throw new InvalidJwkException('Failed to get jwk details', 404);
        }

        $keyInfo = $this->getOpenSslDetails($publicKeyContent);
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

    /**
     * @codeCoverageIgnore
     * @param string $path
     * @return bool|string
     */
    public function getOpenSslDetails(
        string $content
    ) {
        return openssl_pkey_get_details(
            openssl_get_publickey($content)
        );
    }

    /**
     * @codeCoverageIgnore
     * @param string $path
     * @return bool|string
     */
    public function getFileContent(
        string $path
    ) {
        return file_get_contents($path);
    }
}
