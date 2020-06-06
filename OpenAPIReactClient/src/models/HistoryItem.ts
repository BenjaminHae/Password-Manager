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
 * @interface HistoryItem
 */
export interface HistoryItem {
    /**
     * 
     * @type {string}
     * @memberof HistoryItem
     */
    userAgent?: string;
    /**
     * 
     * @type {string}
     * @memberof HistoryItem
     */
    iP?: string;
    /**
     * 
     * @type {number}
     * @memberof HistoryItem
     */
    time?: number;
    /**
     * 
     * @type {string}
     * @memberof HistoryItem
     */
    action?: HistoryItemActionEnum;
    /**
     * 
     * @type {string}
     * @memberof HistoryItem
     */
    actionResult?: string;
}

export function HistoryItemFromJSON(json: any): HistoryItem {
    return HistoryItemFromJSONTyped(json, false);
}

export function HistoryItemFromJSONTyped(json: any, ignoreDiscriminator: boolean): HistoryItem {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'userAgent': !exists(json, 'UserAgent') ? undefined : json['UserAgent'],
        'iP': !exists(json, 'IP') ? undefined : json['IP'],
        'time': !exists(json, 'Time') ? undefined : json['Time'],
        'action': !exists(json, 'Action') ? undefined : json['Action'],
        'actionResult': !exists(json, 'ActionResult') ? undefined : json['ActionResult'],
    };
}

export function HistoryItemToJSON(value?: HistoryItem | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'UserAgent': value.userAgent,
        'IP': value.iP,
        'Time': value.time,
        'Action': value.action,
        'ActionResult': value.actionResult,
    };
}

/**
* @export
* @enum {string}
*/
export enum HistoryItemActionEnum {
    Login = 'Login',
    ChangePassword = 'ChangePassword',
    Registration = 'Registration'
}


