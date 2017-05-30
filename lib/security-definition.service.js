
'strict mode';

const   zlog = require('zlog'),
    _ = require('lodash');

const UUID = require('uuid');

const assert = require('assert');



UUID.generate = UUID.v4;

let dictionary,
    resourceTypes,
    policies,
    conditionFactories;

module.exports = load;

var logger = zlog.getLogger('zerv/security/definition');


/**
 * Collect the information security based and validate that everything works together.
 *
 * Prevent from using settings, policy name, resource name, data structure that are incorrect.
 *
 * 
 * @param <object> : This object contains the following
 * - dictionary: an array of protected resource objects
 * - policies: an array of policy objects
 * - resourceSettings: an array of resource type objects
 *
 * @retuns a new object
 * - dictionary: an array of protected resource objects
 * - policies: an array of policy objects
 * - resourceSettings: an array of resource type objects
 
 */
function load(security) {
    try {
        logger.info('Checking security policy data integrity...');
        initializeResourceTypes(security.resourceTypes, security.conditionFactories);
        initializeDictionary(security.dictionary);
        initializePolicies(security.policies);
        logger.info('Security policy data integrity PASSED.');

        return {
            conditionFactories,
            dictionary,
            resourceTypes,
            policies
        };
    } catch (e) {
        logger.fatal('Security policy data integrity FAILED.');
        logger.error(e.message);
        throw new Error('Invalid Application Security Configuration');
    }

}
////////////////////////////////////////////////////    



/**
 * collect the resource types and make sure they have the requirements
 */
function initializeResourceTypes(resourceTypeList, conditionFactoryList) {
    conditionFactories = conditionFactoryList;
    conditionFactories.find = findConditionFactory;

    resourceTypes = [];
    resourceTypes.find = findResourceType;



    resourceTypes.findSetting = findSetting;

    _.forEach(resourceTypeList, function(resourceType, typeName) {
        try {
            addResourceType(resourceType);
        } catch (e) {
            e.message += ' - invalid resource type [' + typeName + ']: ' + JSON.stringify(resourceType);
            throw e;
        }
    });

    // function findSetting(resourceType, setting) {
    //     return _.find(resourceType.settings, { value: setting });
    // };

    function findSetting(typeName, setting) {
        return _.find(resourceTypes.find(typeName).settings, { value: setting });
    };

    function findResourceType(type) {
        // on the backend, the apply code if the the type
        // if (_.isFunction(type)) {
        //     return {
        //         target: type.name,
        //         apply: type.apply
        //     };
        // }

        var definition = _.find(resourceTypes, { name: type });
        if (!definition) {
            throw new Error('Undefined resource type [' + type + '].');
        }
        return definition;
    };

    function findConditionFactory(factoryName) {
        var factory = _.find(conditionFactories, { factory: factoryName });
        if (!factory) {
            throw new Error('Undefined condition factory [' + factoryName + ']. Check your security config.');
        }
        return factory;
    };

}

function addResourceType(resourceTypeData) {
    var resourceType = _.assign({}, resourceTypeData);
    assert(resourceType.name, 'name property is required');
    logger.debug('Add resource type %b', resourceType.name);
    assert(!_.find(resourceTypes, { name: resourceType.name }), 'Duplicated resource type');
    assert(resourceType.env, 'env property is required');
    if (resourceType.env.indexOf('server') !== -1) {
        assert(_.isFunction(resourceType.apply), 'Apply function is required in server protected resource type');
    }
    resourceTypes.push(resourceType);
}



/**
 * Make sure that the dictionary is valid.
 *
 */
function initializeDictionary(protectedResources) {
    dictionary = [];
    dictionary.findProtectedResourceByName = findProtectedResourceByName;
    protectedResources.forEach(function(protectedResource) {
        try {
            addResourceToDictionary(protectedResource);
        } catch (e) {
            e.message += ' - invalid protected resource in dictionary: ' + JSON.stringify(protectedResource);
            throw e;
        }
    });


    /**
     *  find a protected resource in the dictionary by its name
     *
     */
    function findProtectedResourceByName(name) {
        var protectedResource = _.find(dictionary, { name: name });
        // if (!protectedResource) {
        //     throw new Error('Undefined protected resource in the dictionary:' + name);
        // }
        return protectedResource;

    }
}

function addResourceToDictionary(protectedResourceData) {
    var protectedResource = _.assign({}, protectedResourceData);
    assert(protectedResource.name, 'Name is required');
    logger.debug('Add resource %b to dictionary', protectedResource.name);

    assert(protectedResource.type, 'type is required');
    assert(protectedResource.locator, 'locator is required');
    assert(protectedResource.defaultSetting, 'defaultSetting is required');
    var resourceType = resourceTypes.find(protectedResource.type);
    assert(resourceType, 'Provided type is unknown');
    // protectedResource.type = resourceType;

    var settingObj = resourceTypes.findSetting(resourceType.name, protectedResource.defaultSetting);

    assert(settingObj, 'defaultSetting [' + protectedResource.defaultSetting + '] is unknown to type [' + protectedResource.type + ']');


    assert(!_.find(dictionary, { name: protectedResource.name }), 'Duplicated protected resource [' + protectedResource.name + ']');

    protectedResource.id = UUID.generate();
    dictionary.push(protectedResource);
}


// ---------------------------------------------------------------------------------------
/**
 * Collect policies and make sure they are valid.
 */
function initializePolicies(policyList) {
    policies = [];
    policyList.forEach(function(policy) {
        try {
            addPolicy(policy);
        } catch (e) {
            e.message += ' - invalid policy [' + policy.name + ']';
            throw e;
        }
    });
    // return policies;


}
/**
 * Make sure that the policy is valid.
 *
 * - no duplicated policy
 * - default setting must exists
 * - resources define in each policy setting must exist
 *
 * This will help developer not to enter wrong or missing information.
 *
 * - protected resource type must exists
 * - no duplicated resources
 */

function addPolicy(policy) {
    assert(policy.name, 'Name is required');
    logger.debug('Add policy %b', policy.name);
    assert(policy.settings, 'Settings is required');

    assert(!_.find(policies, { name: policy.name }), 'Duplicated policy [' + policy.name + ']');

    // assert(policy.defaultSetting, 'defaultSettings is required');    
    // assert(policy.settings[policy.defaultSetting], 'The policy default setting [' + policy.defaultSettings + '] does not exist');


    policy.settings.forEach(function(config) {
        try {
            checkPolicySetting(config);
        } catch (e) {
            e.message += ' - invalid policy setting: ' + JSON.stringify(config);
            throw e;
        }
    });
    if (policy.defaultSetting) {
        assert(_.find(policy.settings, { setting: policy.defaultSetting }), 'defaultSetting [' + policy.defaultSetting + '] is incorrect');
    }

    policies.push(policy);
}

function checkPolicySetting(config) {
    assert(config.setting, 'setting is required in policy settings');

    // a policy might have a setting that does not list protected resource. It is fine.
    // it is useful if the default behavior is preferred. ex by admin console is disable in the protected resource.
    if (!config.protectedResources) {
        config.protectedResources = [];
    } else {
        config.protectedResources.forEach(function(config) {
            try {
                checkPolicyProtectedResource(config);
            } catch (e) {
                e.message += ' - invalid protected resource [' + config.resource + ']';
                throw e;
            }
        });
    }

}

function checkPolicyProtectedResource(config) {
    var protectedResource = dictionary.findProtectedResourceByName(config.resource);
    assert(protectedResource, 'Resource [' + config.resource + '] is not defined in the dictionary');
    assert(config.setting, 'Setting is required');

    // check if protected resource used by policy is set with correct setting                
    var resourceType = resourceTypes.find(protectedResource.type);
    assert(resourceTypes.findSetting(protectedResource.type, config.setting), 'Resource [' + config.resource + '] uses an undefined setting [' + config.setting + ']. Allowed values by its type [' + resourceType.name + '] are [' + _.map(resourceType.settings, 'value') + ']');
}

