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

namespace Nelmio\SecurityBundle\SignedCookie;

class SignableCookieChecker implements SignableCookieCheckerInterface
{
    /**
     * @var string[]
     */
    private array $signableCookieNames;

    private bool $containsWildcard;

    /**
     * @param string[] $signableCookieNames
     */
    public function __construct(array $signableCookieNames)
    {
        $this->signableCookieNames = $signableCookieNames;
        $this->containsWildcard = \in_array('*', $this->signableCookieNames, true);
    }

    public function isSignableCookie(string $name): bool
    {
        if (\in_array($name, $this->signableCookieNames, true)) {
            return true;
        }

        return $this->containsWildcard && $name !== session_name();
    }
}
