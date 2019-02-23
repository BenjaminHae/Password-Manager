<?php
/**
 * AccountId
 *
 * PHP version 5
 *
 * @category Class
 * @package  OpenAPI\Server\Model
 * @author   OpenAPI Generator team
 * @link     https://github.com/openapitools/openapi-generator
 */

/**
 * Password Manager
 *
 * This is a password manager server.
 *
 * OpenAPI spec version: 0.0.1
 * Contact: test@te.st
 * Generated by: https://github.com/openapitools/openapi-generator.git
 *
 */

/**
 * NOTE: This class is auto generated by the openapi generator program.
 * https://github.com/openapitools/openapi-generator
 * Do not edit the class manually.
 */

namespace OpenAPI\Server\Model;

use Symfony\Component\Validator\Constraints as Assert;
use JMS\Serializer\Annotation\Type;
use JMS\Serializer\Annotation\SerializedName;

/**
 * Class representing the AccountId model.
 *
 * @package OpenAPI\Server\Model
 * @author  OpenAPI Generator team
 */
class AccountId 
{
        /**
     * @var int|null
     * @SerializedName("index")
     * @Assert\Type("int")
     * @Type("int")
     */
    protected $index;

    /**
     * @var string|null
     * @SerializedName("name")
     * @Assert\Type("string")
     * @Type("string")
     */
    protected $name;

    /**
     * @var string|null
     * @SerializedName("additional")
     * @Assert\Type("string")
     * @Type("string")
     */
    protected $additional;

    /**
     * @var string|null
     * @SerializedName("password")
     * @Assert\Type("string")
     * @Type("string")
     */
    protected $password;

    /**
     * Constructor
     * @param mixed[] $data Associated array of property values initializing the model
     */
    public function __construct(array $data = null)
    {
        $this->index = isset($data['index']) ? $data['index'] : null;
        $this->name = isset($data['name']) ? $data['name'] : null;
        $this->additional = isset($data['additional']) ? $data['additional'] : null;
        $this->password = isset($data['password']) ? $data['password'] : null;
    }

    /**
     * Gets index.
     *
     * @return int|null
     */
    public function getIndex()
    {
        return $this->index;
    }

    /**
     * Sets index.
     *
     * @param int|null $index
     *
     * @return $this
     */
    public function setIndex($index = null)
    {
        $this->index = $index;

        return $this;
    }

    /**
     * Gets name.
     *
     * @return string|null
     */
    public function getName()
    {
        return $this->name;
    }

    /**
     * Sets name.
     *
     * @param string|null $name
     *
     * @return $this
     */
    public function setName($name = null)
    {
        $this->name = $name;

        return $this;
    }

    /**
     * Gets additional.
     *
     * @return string|null
     */
    public function getAdditional()
    {
        return $this->additional;
    }

    /**
     * Sets additional.
     *
     * @param string|null $additional
     *
     * @return $this
     */
    public function setAdditional($additional = null)
    {
        $this->additional = $additional;

        return $this;
    }

    /**
     * Gets password.
     *
     * @return string|null
     */
    public function getPassword()
    {
        return $this->password;
    }

    /**
     * Sets password.
     *
     * @param string|null $password
     *
     * @return $this
     */
    public function setPassword($password = null)
    {
        $this->password = $password;

        return $this;
    }
}


