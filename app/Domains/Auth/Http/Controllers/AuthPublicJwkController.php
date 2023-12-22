<?php

namespace App\Domains\Auth\Http\Controllers;

use App\Domains\Auth\Businesses\AuthPublicJwkBusiness;
use App\Http\Controllers\BaseController;
use Illuminate\Http\Request;
use ResponseJson\ResponseJson;

class AuthPublicJwkController extends BaseController
{
    private $authPublicJwkBusiness;
    private $response;

    /**
     * constructor
     * @param AuthGenerateBusiness $authGenerateBusiness
     * @param ResponseJson $response
     * @return void
     */
    public function __construct(
        AuthPublicJwkBusiness $authPublicJwkBusiness,
        ResponseJson $response
    ) {
        $this->authPublicJwkBusiness = $authPublicJwkBusiness;
        $this->response = $response;
    }

    /**
     * process the request
     * @param string $context
     * @param Request $request
     */
    public function process(
        string $context,
        Request $request
    ) {
        $dataResponse = $this->authPublicJwkBusiness->process(
            $context
        );

        $result = $this->response->response(
            $request->requestId,
            $request->startProfile,
            $request->jwtToken,
            $dataResponse
        );

        return response()->json(
            $result,
            200,
            [],
            JSON_UNESCAPED_SLASHES |
            JSON_UNESCAPED_UNICODE
        );
    }
}
