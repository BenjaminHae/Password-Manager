<?php
/**
 * ChangePassword
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
 * The version of the OpenAPI document: 0.0.1
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
 * Class representing the ChangePassword model.
 *
 * @package OpenAPI\Server\Model
 * @author  OpenAPI Generator team
 */
class ChangePassword 
{
        /**
     * @var string|null
     * @SerializedName("newPassword")
     * @Assert\Type("string")
     * @Type("string")
     */
    protected $newPassword;

    /**
     * @var OpenAPI\Server\Model\AccountId[]|null
     * @SerializedName("accounts")
     * @Assert\All({
     *   @Assert\Type("OpenAPI\Server\Model\AccountId")
     * })
     * @Type("array<OpenAPI\Server\Model\AccountId>")
     */
    protected $accounts;

    /**
     * Constructor
     * @param mixed[] $data Associated array of property values initializing the model
     */
    public function __construct(array $data = null)
    {
        $this->newPassword = isset($data['newPassword']) ? $data['newPassword'] : null;
        $this->accounts = isset($data['accounts']) ? $data['accounts'] : null;
    }

    /**
     * Gets newPassword.
     *
     * @return string|null
     */
    public function getNewPassword()
    {
        return $this->newPassword;
    }

    /**
     * Sets newPassword.
     *
     * @param string|null $newPassword
     *
     * @return $this
     */
    public function setNewPassword($newPassword = null)
    {
        $this->newPassword = $newPassword;

        return $this;
    }

    /**
     * Gets accounts.
     *
     * @return OpenAPI\Server\Model\AccountId[]|null
     */
    public function getAccounts()
    {
        return $this->accounts;
    }

    /**
     * Sets accounts.
     *
     * @param OpenAPI\Server\Model\AccountId[]|null $accounts
     *
     * @return $this
     */
    public function setAccounts(array $accounts = null)
    {
        $this->accounts = $accounts;

        return $this;
    }
}


