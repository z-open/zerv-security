'strict mode';

const _ = require('lodash');
const zlog = require('zlog');
zlog.setRootLogger('NONE');

var security = require("../lib/zerv-security");

describe("Security", function () {
    beforeEach(function () {
    });


    it("should validate policy", function () {
        security.load({
            dictionary: [],
            resourceTypes: [],
            policies: [createPolicy],
            findUserByTenantIdAndId: _.noop,
            findRoleByUser: _.noop,
            defaultRole: 'admin',
            conditionFactories: []
        });
    });
    


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
                            resource: 'Accoun Screen Form',
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
                            resource: 'Accoun Screen Form',
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
                            resource: 'Accoun Screen Form',
                            setting: 'create'
                        }
                    ]
                }
            ]
        };
    }







});