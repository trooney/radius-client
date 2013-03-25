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

    public $host = null;

    public $port = null;

    public $secret = null;

    public $nasHost = null;

    public $timeout = 5;

    public $retries = 1;

    public function __construct($host, $port, $secret, $nasHost = null)
    {
        $this->host = $host;
        $this->port = $port;
        $this->secret = $secret;
        $this->nasHost = $nasHost;

        if (!extension_loaded('radius')) {
            throw new RadiusException('Radius module not installed.');
        }

        if (!$this->radius = radius_auth_open()) {
            $msg = radius_strerror($this->radius);
            throw new RadiusException('Failed to open radius handle: ' . $msg);
        }

        $this->addServer($host, $port, $secret);

    }

    public function __destruct()
    {
        if ($this->radius) {
            radius_close($this->radius);
        }
    }

    public function addServer($host, $port = 1813, $secret = null)
    {
        if (!radius_add_server($this->radius, $host, $port, $secret, $this->timeout, $this->retries)) {
            $msg = radius_strerror($this->radius);
            throw new RadiusException('Failed to add radius server: ' . $msg);
        }
    }

    public function authenticate($username, $password, $nasHost = null)
    {

        $ipAttrs = array(
            RADIUS_NAS_IP_ADDRESS => $nasHost ?: $this->nasHost,
        );

        $binaryAttrs = array(
            RADIUS_USER_NAME => $username,
            RADIUS_USER_PASSWORD => $password,
        );

        $ipAttrs = array_filter($ipAttrs);
        $binaryAttrs = array_filter($binaryAttrs);

        $response = $this->_request(RADIUS_ACCESS_REQUEST, $ipAttrs, $binaryAttrs);

        switch ($response) {
            case RADIUS_ACCESS_ACCEPT:
                return true;
                break;
            case RADIUS_ACCESS_REJECT:
            case RADIUS_ACCESS_CHALLENGE:
                return false;
                break;
            default:
                $msg = radius_strerror($this->radius);
                throw new RadiusException('Radius returned an error: ' . $msg);
        }

    }

    public function _request($type, array $ipAttributes = array(), array $binaryAttributes = array())
    {
        if (!radius_create_request($this->radius, RADIUS_ACCESS_REQUEST)) {
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