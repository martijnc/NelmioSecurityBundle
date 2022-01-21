<?php

declare(strict_types=1);

/*
 * This file is part of the Nelmio SecurityBundle.
 *
 * (c) Nelmio <hello@nelm.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Nelmio\SecurityBundle\EventListener;

use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * @final
 */
class ForcedSslListener
{
    private $hstsMaxAge;
    private $hstsSubdomains;
    private $hstsPreload;
    private $whitelist;
    private $hosts;
    private $redirectStatusCode;

    public function __construct($hstsMaxAge, $hstsSubdomains, $hstsPreload = false, array $whitelist = [], array $hosts = [], $redirectStatusCode = 302)
    {
        $this->hstsMaxAge = $hstsMaxAge;
        $this->hstsSubdomains = $hstsSubdomains;
        $this->hstsPreload = $hstsPreload;
        $this->whitelist = $whitelist ? '('.implode('|', $whitelist).')' : null;
        $this->hosts = $hosts ? '('.implode('|', $hosts).')' : null;
        $this->redirectStatusCode = $redirectStatusCode;
    }

    public function onKernelRequest(RequestEvent $e)
    {
        if (HttpKernelInterface::MASTER_REQUEST !== $e->getRequestType()) {
            return;
        }

        $request = $e->getRequest();

        // skip SSL & non-GET/HEAD requests
        if ($request->isSecure() || !$request->isMethodSafe()) {
            return;
        }

        // skip whitelisted URLs
        if ($this->whitelist && preg_match('{'.$this->whitelist.'}i', $request->getPathInfo() ?: '/')) {
            return;
        }

        // skip non-listed hosts
        if ($this->hosts && !preg_match('{'.$this->hosts.'}i', $request->getHost() ?: '/')) {
            return;
        }

        // redirect the rest to SSL
        $e->setResponse(new RedirectResponse('https://'.substr($request->getUri(), 7), $this->redirectStatusCode));
    }

    public function onKernelResponse(ResponseEvent $e)
    {
        if (HttpKernelInterface::MASTER_REQUEST !== $e->getRequestType()) {
            return;
        }

        // skip non-SSL requests as per the RFC
        // "An HSTS Host MUST NOT include the STS header field in HTTP responses conveyed over non-secure transport."
        $request = $e->getRequest();
        if (!$request->isSecure()) {
            return;
        }

        $response = $e->getResponse();

        if (!$response->headers->has('Strict-Transport-Security')) {
            $header = 'max-age='.$this->hstsMaxAge;
            $header .= ($this->hstsSubdomains ? '; includeSubDomains' : '');
            $header .= ($this->hstsPreload ? '; preload' : '');
            $response->headers->set('Strict-Transport-Security', $header);
        }
    }
}