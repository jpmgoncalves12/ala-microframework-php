<?php

namespace App\Domains\Auth\Http\Controllers;

use App\Domains\Auth\Businesses\AuthPublicJwkBusiness;
use App\Http\Controllers\BaseController;
use Illuminate\Http\Request;
use ResponseJson\ResponseJson;

class AuthPublicJwkController extends BaseController
{
    private $authPublicJwkBusiness;

    /**
     * constructor
     * @param AuthGenerateBusiness $authGenerateBusiness
     * @param ResponseJson $response
     * @return void
     */
    public function __construct(AuthPublicJwkBusiness $authPublicJwkBusiness)
    {
        $this->authPublicJwkBusiness = $authPublicJwkBusiness;
    }

    /**
     * process the request
     * @param string $context
     * @param Request $request
     */
    public function process(
        string $context
    ) {
        $dataResponse = $this->authPublicJwkBusiness->process(
            $context
        );

        return response()->json(
            $dataResponse,
            200,
            [],
            JSON_UNESCAPED_SLASHES |
            JSON_UNESCAPED_UNICODE
        );
    }
}
