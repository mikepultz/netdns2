<?php declare(strict_types=1);

/**
 * DNS Library for handling lookups and updates.
 *
 * Copyright (c) 2020, Mike Pultz <mike@mikepultz.com>. All rights reserved.
 *
 * See LICENSE for more details.
 *
 * @category  Networking
 * @package   Net_DNS2
 * @author    Mike Pultz <mike@mikepultz.com>
 * @copyright 2020 Mike Pultz <mike@mikepultz.com>
 * @license   http://www.opensource.org/licenses/bsd-license.php  BSD License
 * @link      https://netdns2.com/
 */

class Net_DNS2_Exception extends Exception
{
    public function __construct(
        string $message = '',
        int $code = 0,
        ?\Throwable $previous = null,
        private ?Net_DNS2_Packet_Request $request = null,
        private ?Net_DNS2_Packet_Response $response = null,
    ) {
        parent::__construct($message, $code, $previous);
    }

    public function getRequest(): ?Net_DNS2_Packet_Request
    {
        return $this->request;
    }

    public function getResponse(): ?Net_DNS2_Packet_Response
    {
        return $this->response;
    }
}
