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
 * @interface ModelFile
 */
export interface ModelFile {
    /**
     * 
     * @type {number}
     * @memberof ModelFile
     */
    index?: number;
    /**
     * 
     * @type {string}
     * @memberof ModelFile
     */
    name?: string;
    /**
     * 
     * @type {string}
     * @memberof ModelFile
     */
    key?: string;
}

export function ModelFileFromJSON(json: any): ModelFile {
    return ModelFileFromJSONTyped(json, false);
}

export function ModelFileFromJSONTyped(json: any, ignoreDiscriminator: boolean): ModelFile {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'index': !exists(json, 'index') ? undefined : json['index'],
        'name': !exists(json, 'name') ? undefined : json['name'],
        'key': !exists(json, 'key') ? undefined : json['key'],
    };
}

export function ModelFileToJSON(value?: ModelFile | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'index': value.index,
        'name': value.name,
        'key': value.key,
    };
}

