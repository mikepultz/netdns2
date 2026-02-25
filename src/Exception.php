<?php declare(strict_types=1);

namespace Net\DNS2;

use Net\DNS2\Packet\Request;
use Net\DNS2\Packet\Response;

class Exception extends \Exception
{
    public function __construct(
        string $message = '',
        int $code = 0,
        ?\Throwable $previous = null,
        private ?Request $request = null,
        private ?Response $response = null,
    ) {
        parent::__construct($message, $code, $previous);
    }

    public function getRequest(): ?Request
    {
        return $this->request;
    }

    public function getResponse(): ?Response
    {
        return $this->response;
    }
}
