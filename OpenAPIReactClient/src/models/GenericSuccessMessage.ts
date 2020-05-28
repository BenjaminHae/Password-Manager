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
 * @interface GenericSuccessMessage
 */
export interface GenericSuccessMessage {
    /**
     * 
     * @type {string}
     * @memberof GenericSuccessMessage
     */
    status?: string;
    /**
     * 
     * @type {string}
     * @memberof GenericSuccessMessage
     */
    message?: string;
}

export function GenericSuccessMessageFromJSON(json: any): GenericSuccessMessage {
    return GenericSuccessMessageFromJSONTyped(json, false);
}

export function GenericSuccessMessageFromJSONTyped(json: any, ignoreDiscriminator: boolean): GenericSuccessMessage {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'status': !exists(json, 'status') ? undefined : json['status'],
        'message': !exists(json, 'message') ? undefined : json['message'],
    };
}

export function GenericSuccessMessageToJSON(value?: GenericSuccessMessage | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'status': value.status,
        'message': value.message,
    };
}

