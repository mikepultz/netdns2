<?php declare(strict_types=1);

namespace Net\DNS2;


use Net\DNS2\Packet\Request;
use Net\DNS2\Packet\Response;
/**
 * DNS Library for handling lookups and updates.
 *
 * Copyright (c) 2020, Mike Pultz <mike@mikepultz.com>. All rights reserved.
 *
 * See LICENSE for more details.
 *
 * @category  Networking
 * @package   \Net\DNS2\DNS2
 * @author    Mike Pultz <mike@mikepultz.com>
 * @copyright 2020 Mike Pultz <mike@mikepultz.com>
 * @license   http://www.opensource.org/licenses/bsd-license.php  BSD License
 * @link      https://netdns2.com/
 */

class Exception extends \Exception
{
    public function __construct(
        string $message = '',
        int $code = 0,
        ?\Throwable $previous = null,
        private ?\Net\DNS2\Packet\Request $request = null,
        private ?\Net\DNS2\Packet\Response $response = null,
    ) {
        parent::__construct($message, $code, $previous);
    }

    public function getRequest(): ?\Net\DNS2\Packet\Request
    {
        return $this->request;
    }

    public function getResponse(): ?\Net\DNS2\Packet\Response
    {
        return $this->response;
    }
}
