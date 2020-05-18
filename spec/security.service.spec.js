'strict mode';

const _ = require('lodash');
const zlog = require('zimit-zlog');
zlog.setRootLogger('ALL');

var security = require("../lib/security.service");

describe("Security", function () {
    beforeEach(function () {
    });


    it("should validate policy", function () {
        security.load({
            dictionary: createDictionary(),
            resourceTypes: createDictionaryResourceTypes(),
            policies: [createPolicy()],
            findUserByTenantIdAndId: _.noop,
            findRoleByUser: _.noop,
            defaultRole: 'admin',
            conditionFactories: []
        });

    });

    it("should not validate policy due to", function () {
        const load = function () {
            security.load({
                dictionary: [],
                resourceTypes: [],
                policies: [createPolicy()],
                findUserByTenantIdAndId: _.noop,
                findRoleByUser: _.noop,
                defaultRole: 'admin',
                conditionFactories: []
            });
        }

        expect(load).toThrowError('Invalid Application Security Configuration');
    });

    function createDictionaryResourceTypes() {
        return [{
            name: 'AppMenuItem',
            env: 'client',
            settings: [
                { value: 'show', priority: 1 },
                { value: 'hide', priority: 0 }
            ]
        },
        {
            name: 'screenForm',
            env: 'client',
            settings: [
                { value: 'readOnly', priority: 1 },
                { value: 'edit', priority: 0 },
                { value: 'create', priority: 0 }
            ]
        }];
    }

    function createDictionary() {
        return [
            {
                // name is not useful in prod mode...but it is in debug to know what we are protecting...
                name: 'Account menu',
                type: 'AppMenuItem',
                locator: 'accountOption',
                defaultSetting: 'show'
            },
            {
                // name is not useful in prod mode...but it is in debug to know what we are protecting...
                name: 'Account Screen Form',
                type: 'screenForm',
                locator: 'account',
                defaultSetting: 'readOnly'
            },
        ];
    }

    function createPolicy() {
        return {
            name: 'Account Policy',
            defaultSetting: null,
            description: 'Account Security Policy',
            settings:
            [
                {
                    setting: 'read',
                    notes: 'This provides user access to review accounts.',
                    protectedResources: [
                        {
                            resource: 'Account menu',
                            setting: 'show'
                        },
                        {
                            resource: 'Account Screen Form',
                            setting: 'readOnly'
                        }
                    ]
                },
                {
                    setting: 'Update',
                    notes: 'This provides user access to review/edit accounts.',
                    protectedResources: [
                        {
                            resource: 'Account menu',
                            setting: 'show'
                        },
                        {
                            resource: 'Account Screen Form',
                            setting: 'edit'
                        }
                    ]
                },
                {
                    setting: 'create',
                    notes: 'This provides user access to create,edit,review accounts.',
                    protectedResources: [
                        {
                            resource: 'Account menu',
                            setting: 'show'
                        },
                        {
                            resource: 'Account Screen Form',
                            setting: 'create'
                        }
                    ]
                }
            ]
        };
    }







});