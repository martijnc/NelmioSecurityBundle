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

namespace Nelmio\SecurityBundle\Tests\SignedCookie;

use Nelmio\SecurityBundle\SignedCookie\SignableCookieChecker;
use PHPUnit\Framework\TestCase;

class SignableCookieCheckerTest extends TestCase
{
    public function testMatchesAllowListedCookie(): void
    {
        $checker = new SignableCookieChecker(['foobar']);
        $this->assertTrue($checker->isSignableCookie('foobar'));
    }

    public function testDoesNotMatchUnknownCookie(): void
    {
        $checker = new SignableCookieChecker(['foobar']);
        $this->assertFalse($checker->isSignableCookie('bar'));
    }

    public function testDoesNotMatchEmptyAllowlist(): void
    {
        $checker = new SignableCookieChecker([]);
        $this->assertFalse($checker->isSignableCookie('foobar'));
    }

    public function testMatchesCookiesWhenWildcard(): void
    {
        $checker = new SignableCookieChecker(['*']);
        $this->assertTrue($checker->isSignableCookie('i_want_to_be_signed'));
        $this->assertTrue($checker->isSignableCookie('foobar'));
    }

    public function testDoesNotMatchesSessionCookieWhenWildcard(): void
    {
        $sessionName = session_name();
        \assert(\is_string($sessionName));

        $checker = new SignableCookieChecker(['*']);
        $this->assertTrue($checker->isSignableCookie('foobar'));
        $this->assertFalse($checker->isSignableCookie($sessionName));
    }

    public function testMatchesSessionsCookieWhenAllowlisted(): void
    {
        $sessionName = session_name();
        \assert(\is_string($sessionName));

        $checker = new SignableCookieChecker(['*', $sessionName]);
        $this->assertTrue($checker->isSignableCookie($sessionName));
    }
}
