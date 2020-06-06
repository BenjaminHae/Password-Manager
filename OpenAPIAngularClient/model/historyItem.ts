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


export interface HistoryItem { 
    UserAgent?: string;
    IP?: string;
    Time?: number;
    Action?: HistoryItem.ActionEnum;
    ActionResult?: string;
}
export namespace HistoryItem {
    export type ActionEnum = 'Login' | 'ChangePassword' | 'Registration';
    export const ActionEnum = {
        Login: 'Login' as ActionEnum,
        ChangePassword: 'ChangePassword' as ActionEnum,
        Registration: 'Registration' as ActionEnum
    };
}

