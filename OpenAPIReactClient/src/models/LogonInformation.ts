/* tslint:disable */
/* eslint-disable */
/**
 * Password Manager
 * This is a password manager server.
 *
 * The version of the OpenAPI document: 0.0.1
 * Contact: test@te.st
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */

import { exists, mapValues } from '../runtime';
/**
 * 
 * @export
 * @interface LogonInformation
 */
export interface LogonInformation {
    /**
     * 
     * @type {string}
     * @memberof LogonInformation
     */
    username?: string;
    /**
     * 
     * @type {string}
     * @memberof LogonInformation
     */
    password?: string;
}

export function LogonInformationFromJSON(json: any): LogonInformation {
    return LogonInformationFromJSONTyped(json, false);
}

export function LogonInformationFromJSONTyped(json: any, ignoreDiscriminator: boolean): LogonInformation {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'username': !exists(json, 'username') ? undefined : json['username'],
        'password': !exists(json, 'password') ? undefined : json['password'],
    };
}

export function LogonInformationToJSON(value?: LogonInformation | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'username': value.username,
        'password': value.password,
    };
}

