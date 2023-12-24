<?php

namespace App\Domains\Auth\Http\Validators;

use App\Http\Validators\BaseValidator;

class AuthGenerateValidator extends BaseValidator
{
    /**
     * get rules for this request
     * @return array
     */
    public function getRules()
    {
        if ($this->getConfig('app')['usePemToSignJWT']) {
            return [
                'context' => 'required|string',
            ];
        }

        return [
            'token' => 'required|string',
            'secret' => 'required|string',
        ];
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
