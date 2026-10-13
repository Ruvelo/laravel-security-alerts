<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlerts\Tests\Support;

use Illuminate\Support\Facades\Http;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * A PSR-18 client that sends through Laravel's Http facade, so the tests can
 * use Http::fake(), Http::preventStrayRequests() and Http::assertSent(): the
 * package's own client is bound to this one, and nothing reaches the network.
 */
final class HttpFacadeClient implements ClientInterface
{
    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $headers = array_map(fn (array $values): string => implode(', ', $values), $request->getHeaders());
        unset($headers['Host']);

        return Http::withHeaders($headers)
            ->withBody((string) $request->getBody(), $request->getHeaderLine('Content-Type') ?: 'application/octet-stream')
            ->send($request->getMethod(), (string) $request->getUri())
            ->toPsrResponse();
    }
}
