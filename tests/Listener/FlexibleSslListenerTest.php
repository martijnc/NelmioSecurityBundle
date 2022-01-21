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

namespace Nelmio\SecurityBundle\Tests\Listener;

use Nelmio\SecurityBundle\EventListener\FlexibleSslListener;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\ResponseHeaderBag;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

class FlexibleSslListenerTest extends \PHPUnit\Framework\TestCase
{
    private $kernel;
    private $dispatcher;
    private $listener;

    protected function setUp(): void
    {
        $this->kernel = $this->getMockBuilder(HttpKernelInterface::class)->getMock();
        $this->dispatcher = $this->getMockBuilder(EventDispatcherInterface::class)->getMock();
        $this->listener = new FlexibleSslListener('auth', false, $this->dispatcher);
    }

    public function testKernelRequestWithNonAuthedNonSslRequest()
    {
        $request = Request::create('http://localhost/');

        $event = new RequestEvent($this->kernel, $request, HttpKernelInterface::MASTER_REQUEST);
        $this->listener->onKernelRequest($event);

        $this->assertFalse($event->hasResponse());
    }

    public function testKernelRequestWithAuthedNonSslRequest()
    {
        $request = Request::create('http://localhost/');
        $request->cookies->set('auth', '1');

        $event = new RequestEvent($this->kernel, $request, HttpKernelInterface::MASTER_REQUEST);
        $this->listener->onKernelRequest($event);

        $this->assertTrue($event->hasResponse());
        $this->assertTrue($event->getResponse()->isRedirection());
    }

    public function testKernelRequestWithNonAuthedSslRequest()
    {
        $request = Request::create('https://localhost/');

        $event = new RequestEvent($this->kernel, $request, HttpKernelInterface::MASTER_REQUEST);
        $this->listener->onKernelRequest($event);

        $this->assertFalse($event->hasResponse());
    }

    public function testKernelRequestWithAuthedSslRequest()
    {
        $request = Request::create('https://localhost/');
        $request->cookies->set('auth', '1');

        $event = new RequestEvent($this->kernel, $request, HttpKernelInterface::MASTER_REQUEST);
        $this->listener->onKernelRequest($event);

        $this->assertFalse($event->hasResponse());
    }

    public function testPostLoginKernelResponse()
    {
        $request = Request::create('https://localhost/');

        $response = new Response();

        $event = new ResponseEvent($this->kernel, $request, HttpKernelInterface::MASTER_REQUEST, $response);
        $this->listener->onPostLoginKernelResponse($event);

        $cookies = $response->headers->getCookies(ResponseHeaderBag::COOKIES_ARRAY);
        $this->assertTrue(isset($cookies['']['/']['auth']));
        $this->assertSame('1', $cookies['']['/']['auth']->getValue());
        $this->assertFalse($cookies['']['/']['auth']->isSecure());

        $this->assertTrue(isset($cookies['']['/'][session_name()]));
        $this->assertSame(session_id(), $cookies['']['/'][session_name()]->getValue());
        $this->assertTrue($cookies['']['/'][session_name()]->isSecure());
    }

    public function testKernelRequestSkipsSubReqs()
    {
        $request = Request::create('http://localhost/');
        $request->cookies->set('auth', '1');

        $event = new RequestEvent($this->kernel, $request, HttpKernelInterface::SUB_REQUEST);
        $this->listener->onKernelRequest($event);

        $this->assertFalse($event->hasResponse());
    }

    public function testPostLoginKernelResponseSkipsSubReqs()
    {
        $request = Request::create('https://localhost/');

        $response = new Response();

        $event = new ResponseEvent($this->kernel, $request, HttpKernelInterface::SUB_REQUEST, $response);
        $this->listener->onPostLoginKernelResponse($event);

        $cookies = $response->headers->getCookies(ResponseHeaderBag::COOKIES_ARRAY);
        $this->assertFalse(isset($cookies['']['/']['auth']));
    }

    public function testSecureLogout()
    {
        $response = new RedirectResponse('https://foo');
        $request = $this->getMockBuilder(Request::class)->getMock();
        $token = $this->getMockBuilder(TokenInterface::class)->getMock();

        $this->listener->logout($request, $response, $token);

        $this->assertSame('https://foo', $response->headers->get('Location'));
    }

    public function testUnsecuredLogout()
    {
        $unsecuredLogoutListener = new FlexibleSslListener('auth', true, $this->dispatcher);

        $response = new RedirectResponse('https://foo');
        $request = $this->getMockBuilder(Request::class)->getMock();
        $token = $this->getMockBuilder(TokenInterface::class)->getMock();

        $unsecuredLogoutListener->logout($request, $response, $token);

        $this->assertSame('http://foo', $response->headers->get('Location'));
    }
}