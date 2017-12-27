<?php

namespace RafflesArgentina\ActionBasedPermission\Middleware;

use Lang;
use Closure;

use Illuminate\Contracts\Auth\Guard;

use RafflesArgentina\ActionBasedPermission\Exceptions\ActionBasedPermissionException;

class ActionBasedPermission
{
    protected $auth;

    /**
     * Create a new ActionBasedPermission instance.
     *
     * @param \Illuminate\Contracts\Auth\Guard $auth The Guard implementation.
     */
    public function __construct(Guard $auth)
    {
        $this->auth = $auth;
    }

    /**
     * Handle an incoming request.
     *
     * @param \Illuminate\Http\Request $request The request object.
     * @param \Closure                 $next    The closure.
     * @param string                   $alias   The named route alias.
     *
     * @return mixed
     */
    public function handle($request, Closure $next, $alias = null)
    {
        $actions = [
            'index',
            'create',
            'store',
            'show',
            'edit',
            'update',
            'destroy',
        ];

        $action = explode('@', $request->route()->getActionName())[1];

        $name = $request->route()->getName();

        if ($alias) {
            $name = str_replace($alias.'.', '', $name); 
        }

        if (!in_array($action, $actions) || !$this->auth->user()->can($name)) {

            $resource = explode('.', $name)[0];
            $message = $this->_formatUnauthorizedMessage($action, $resource);

            if ($request->wantsJson()) {
                return $this->_validUnauthorizedJsonResponse($message);
            }

            throw new ActionBasedPermissionException($message);
        }

        return $next($request);
    }

    /**
     * Format the Unauthorized 403 response message.
     *
     * @param string $action   The route action.
     * @param string $resource The route resource.
     *
     * @return string
     */
    private function _formatUnauthorizedMessage($action, $resource)
    {
        $lang = 'action-based-permission.unauthorized.'.$action;
        if (Lang::has($lang)) {
            return trans(
                $lang, [
                'action' => $action,
                'resource' => $resource,
                ]
            );
        }

        $descriptions = [
            'index' => "list {$resource}",
            'show' => "view {$resource}",
            'create' => "show the form to create {$resource}",
            'store' => "store {$resource}",
            'edit' => "show the form to edit {$resource}",
            'update' => "update {$resource}",
            'destroy' => "deactivate or delete {$resource}",
        ];

        return "You are not allowed to {$descriptions[$action]}."; 
    }

    /**
     * Return a valid 403 Unauthorized json response.
     *
     * @param string $message The response message.
     *
     * @return \Illuminate\Http\Response
     */
    private function _validUnauthorizedJsonResponse($message)
    {
        return response()->json(
            [
                'code' => '403',
                'message' => $message,
                'errors' => [],
                'redirect' => '',
            ], 403, [], JSON_PRETTY_PRINT
        );
    }
}
