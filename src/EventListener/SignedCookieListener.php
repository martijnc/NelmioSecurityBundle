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

use Nelmio\SecurityBundle\SignedCookie\SignableCookieChecker;
use Nelmio\SecurityBundle\SignedCookie\SignableCookieCheckerInterface;
use Nelmio\SecurityBundle\Signer\SignerInterface;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;

final class SignedCookieListener
{
    private SignerInterface $signer;

    private SignableCookieCheckerInterface $signableCookieChecker;

    /**
     * @param list<string>|SignableCookieCheckerInterface $signableCookieChecker
     */
    public function __construct(SignerInterface $signer, $signableCookieChecker)
    {
        $this->signer = $signer;

        if ($signableCookieChecker instanceof SignableCookieCheckerInterface) {
            $this->signableCookieChecker = $signableCookieChecker;
        } elseif (\is_array($signableCookieChecker)) {
            $this->signableCookieChecker = new SignableCookieChecker($signableCookieChecker);
            trigger_deprecation(
                'nelmio/security-bundle',
                '3.5',
                'Passing an array with cookie names to the %s constructor is deprecated. Pass `SignableCookieCheckerInterface` instead.',
                self::class
            );
        } else {
            throw new \InvalidArgumentException(sprintf('The %s constructor expects a `SignableCookieCheckerInterface` or array', self::class));
        }
    }

    public function onKernelRequest(RequestEvent $e): void
    {
        if (!$e->isMainRequest()) {
            return;
        }

        $request = $e->getRequest();

        foreach ($request->cookies->keys() as $name) {
            $cookie = $request->cookies->get($name);
            if (!$this->signableCookieChecker->isSignableCookie($name) && !$this->isSignedSessionCookie($name, $cookie)) {
                continue;
            }

            if (null === $cookie) {
                continue;
            }

            if ($this->signer->verifySignedValue($cookie)) {
                $request->cookies->set($name, $this->signer->getVerifiedRawValue($cookie));
            } else {
                $request->cookies->remove($name);
            }
        }
    }

    public function onKernelResponse(ResponseEvent $e): void
    {
        if (!$e->isMainRequest()) {
            return;
        }

        $response = $e->getResponse();

        foreach ($response->headers->getCookies() as $cookie) {
            if (!$this->signableCookieChecker->isSignableCookie($cookie->getName())) {
                continue;
            }

            $response->headers->removeCookie($cookie->getName(), $cookie->getPath(), $cookie->getDomain());
            $signedCookie = new Cookie(
                $cookie->getName(),
                $this->signer->getSignedValue((string) $cookie->getValue()),
                $cookie->getExpiresTime(),
                $cookie->getPath(),
                $cookie->getDomain(),
                $cookie->isSecure(),
                $cookie->isHttpOnly(),
                $cookie->isRaw(),
                $cookie->getSameSite()
            );
            $response->headers->setCookie($signedCookie);
        }
    }

    /**
     * Check for pre 3.5 signed session cookies. To be removed in 4.0.
     */
    private function isSignedSessionCookie(string $name, ?string $value): bool
    {
        if ($name !== session_name() || null === $value) {
            return false;
        }

        return $this->signer->verifySignedValue($value);
    }
}
