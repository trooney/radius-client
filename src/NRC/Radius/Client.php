<?php
/**
 * Radius Authenticator
 *
 * @author Tyler Rooney <tyler@tylerrooney.ca>
 */

namespace NRC\Radius;

use NRC\Radius\Exception\RadiusException;

class Client
{

    /**
     * @var resource rad_handle
     */
    protected $radius = null;

    public $timeout = 5;

    public $retries = 1;

    public function __construct()
    {
        if (!extension_loaded('radius')) {
            throw new RadiusException('Radius module not installed.');
        }

        if (!$this->radius = radius_auth_open()) {
            throw new RadiusException('Failed to open radius handle: ' . $this->lastError());
        }
    }

    public function __destruct()
    {
        if ($this->radius) {
            radius_close($this->radius);
        }
    }

    public function lastError()
    {
        return radius_strerror($this->radius);
    }

    public function addServer($host, $port = 1813, $secret = null)
    {
        if (!radius_add_server($this->radius, $host, $port, $secret, $this->timeout, $this->retries)) {
            throw new RadiusException('Failed to add radius server: ' . $this->lastError());
        }
    }

    public function authenticate($username, $password, $nasHost)
    {

        $ipAttrs = array(
            RADIUS_NAS_IP_ADDRESS => $nasHost,
        );

        $binaryAttrs = array(
            RADIUS_USER_NAME => $username,
            RADIUS_USER_PASSWORD => $password,
        );

        $ipAttrs = array_filter($ipAttrs);
        $binaryAttrs = array_filter($binaryAttrs);

        $response = $this->_request(RADIUS_ACCESS_REQUEST, $ipAttrs, $binaryAttrs);

        if (false === $response) {
            throw new RadiusException('Radius request returned an invalid response: ' . $this->lastError());
        }

        return RADIUS_ACCESS_ACCEPT === $response;
    }

    public function _request($type, array $ipAttributes = array(), array $binaryAttributes = array())
    {
        if (!radius_create_request($this->radius, $type)) {
            throw new RadiusException(radius_strerror($this->radius));
        }

        foreach ($ipAttributes as $attribute => $value) {
            radius_put_addr($this->radius, $attribute, $value);
        }

        foreach ($binaryAttributes as $attribute => $value) {
            radius_put_attr($this->radius, $attribute, $value);
        }

        return radius_send_request($this->radius);
    }

}