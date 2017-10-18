'use strict';

const assert = require('assert');
const Promise = require('promise');
const _ = require('lodash');

const UserPolicy = require('./user-policy.model');
const initSecurity = require('./security-definition.service');
const zlog = require('zlog');

let findRole,
    systemSecurityData;

module.exports = {
    collectClientUserPolicy,
    applyResourcePolicy,
    load,
    getSystemSecurityConfiguration
};

const logger = zlog.getLogger('zerv/security');

/**
 * Collect the information security based and validate that everything works together.
 *
 * @param <object> : This object contains the following
 * - findRole: a function(roleName) that loads the role object and returns a promise
 * - defaultRole : The role name by default.
 * - dictionary: an array of protected resource objects
 * - policies: an array of policy objects
 * - resourceSettings: an array of resource type objects
 * - conditionFactories: an array of services containing the condition methods.
 *
 *
 */
function load(securityConfiguration) {
    if (!securityConfiguration.defaultRole) {
        throw new Error('No default role provided to initialize system security');
    }
    findRole = function(user) {
        return securityConfiguration.findRoleByUser(user).then(function(policyRole) {
            if (!policyRole) {
                logger.info(user.display + ': No defined role. Using configured default role:' + securityConfiguration.defaultRole);
                return securityConfiguration.findRole(securityConfiguration.defaultRole);
            }
            return policyRole;
        });
    };

    module.exports.findUserByTenantIdAndId = securityConfiguration.findUserByTenantIdAndId;

    systemSecurityData = initSecurity(securityConfiguration);
}


function getSystemSecurityConfiguration() {
    if (!systemSecurityData) {
        throw new Error('System security not initialized');
    }
    return systemSecurityData;
}


/**
 *  Apply the user policy to a server resource.
 *
 * The function execute the  protected resource implementation as per its type.
 * The implementation will determine if based on the resource configuration defined the user policy the resource is valid or denied.
 *
 *  example
 *
 *  applyResourcePolicy(user,'api.account.updateOne',{account:account, user:currentUser}).then(function() {
 *              accountService.updateOne(.....)
 *  });
 *
 * 
 *  this would find out which setting the SERVER protected resource should have for under the policy of the provided user.
 *  then apply the setting to the resource (apply code is defined in the resource type)
 *
 *
 * @param <object> user, user object must have permissionRoleCode
 * @param <string> locator, locator is defined in the dictionary. It is necessary to locate the protected resource and its type.
 * @param <object> context param contains key/map value that necessary to calculate the setting (since there might be a condition)
 *
 * @returns a promise with the value returned when applying the setting to the resource
 * - if true, the policy is ENABLED,
 * - if false, the promise is rejected
 * - if an object, the policy is enabled and data is returned.
 *
 */
function applyResourcePolicy(user, protectedResourceLocator, contextParams) {
    // Result will alway be true when there is no user role
    if (!user || !user.permissionRoleCode) {
        return Promise.resolve({
            result: true,
            isSetting: function() {
                logger.error(user.display + ': isSetting() for resource %b is not supported when user is no under a policy', protectedResourceLocator);
                return false;
            }
        });
    }

    return collectServerUserPolicy(user).then(function(userPolicy) {

        const protectedResource = userPolicy.getProtectedResourceByLocator(protectedResourceLocator);
        //return Promise.reject('PROTECTED_RESOURCE_UNDEFINED');

        // let's calculate the setting to know how this resource should behave        
        const setting = protectedResource.calculateSetting(contextParams);

        return Promise.resolve(protectedResource.apply(setting, contextParams))
            .then(function(valid) {
                if (!valid) {
                    logger.warn(user.display + ': Server protected resource %b is denied', protectedResource.name);
                    return Promise.reject('RESOURCE_DENIED');
                }
                return Promise.resolve({
                    result: valid,
                    isSetting: isSetting
                });
            });


        //to test
        function isSetting(settingName) {
            if (settingName === protectedResource.setting) {
                return true;
            }
            // check the setting does exist!!!
            // we don't want some code that handle a setting that does not exist
            assert(systemSecurityData.resourceTypes.findSetting(protectedResource.type, settingName), 'Inexisting setting [' + settingName + '] was passed to isSetting function  to check protected resource [' + protectedResource.type + ']');
            return false;
        }
    });
}


/**
 * the security data contains all active policies.
 *
 * If a protected resource is not listed in a policy, the default value (as defined in dictionary) will be applied by the client.
 */
function collectClientUserPolicy(user) {
    return findUserPolicyData(user)
        .then(function(userPolicies) {
            return formatUserSecurityData(generateUserSecurityDataByEnvironment(user, userPolicies, 'client'));
        });
}

/**
 * collect server policy for this specifig user.
 *
 * @param <object> User object musht have the role, id, revision within
 * @returns security configuration
 */
function collectServerUserPolicy(user) {
    return findUserPolicyData(user)
        .then(function(userPolicies) {
            const securityData = formatUserSecurityData(generateUserSecurityDataByEnvironment(user, userPolicies, 'server'));
            return new UserPolicy(securityData, getPolicyConditionFactory, getResourceTypeFactory);
        });
}


/**
 * the conditionFatories are listed in security config.
 *
 * @returns an object containing all condition functions
 * 
 */
function getPolicyConditionFactory(factoryName) {
    // factory returns all function
    return systemSecurityData.conditionFactories.find(factoryName);
};

/**
 * The backend currently gets the resource type implementation from its resource type definition
 * In the front end, an angular factory is created for each resource type. So this is not consistent but simplifies the configuration on the backend.
 *
 */
function getResourceTypeFactory(resourceType) {
    return {
        target: resourceType.name,
        apply: resourceType.apply
    };
}

/**
 *
 *  format security data and filter protected resources and resource types by environment (client/server)
 *
 *  Notes:
 *  ------
 *  Later on the dictionary and resource types will not be part of this format.
 *  That information should already be in the environment code.
 */
function generateUserSecurityDataByEnvironment(user, userPolicies, env) {
    if (!user.permissionRoleCode || user.isTenantAdmin()) {
        return {
            env: env,
            user: user,
            description: 'Admin - Full access'
        };
    }
    const filteredPolicies = filterPolicyContentByEnvironment(userPolicies, env);
    const filteredDictionary = _.filter(systemSecurityData.dictionary, function(resource) {
        return systemSecurityData.resourceTypes.find(resource.type).env.indexOf(env) !== -1;
    });
    const filteredResourceTypes = _.filter(systemSecurityData.resourceTypes, function(type) {
        return type.env.indexOf(env) !== -1;
    });
    return {
        policies: filteredPolicies,
        dictionary: filteredDictionary,
        resourceTypes: filteredResourceTypes,
        env: env,
        user: user,
        description: userPolicies.description
    };
}
/**
 * format the user data cleanly in order to convey them to other tiers.
 *
 * This format is to be used by UserSecurity object which handles and applies policies to the environment.
 * The reason that dictionary and resourceTypes are part of the userData is because the environment target might not have that information (in the future, this information should be part of the code)
 *
 * @param <object> securityData that contain the necessary user data to rely on to apply a policy.
 *
 * @returns <object> Some formatting of that information since it might need to be synced/ or stored in the session.
 *
 */
function formatUserSecurityData(securityData) {
    const formated = {
        id: 1,
        revision: Date.now(),
        timestamp: {},
        userId: securityData.user.id,
        display: securityData.user.display,
        policies: securityData.policies,
        dictionary: securityData.dictionary,
        resourceTypes: securityData.resourceTypes
    };
    logger.debug('--------------------------------------------------');
    logger.info(securityData.user.display + ': Server Security on %b: %b - id: %b', securityData.env.toUpperCase(), securityData.description, (securityData.user.permissionRoleCode || 'Role has not been defined'));
    logger.debug(JSON.stringify(formated.policies, null, 2) || 'No security enforced.');
    logger.debug('--------------------------------------------------');
    return formated;
}

/**
 *  Policies defines the resources for all protected resources
 *
 *  Filter the policies to keep only what is related to the targeted environment
 *
 *  @param <array> policies
 *  @param <string> env ('client'/'server')
 *
 *  @returns <array> of filtered policies
 */
function filterPolicyContentByEnvironment(userPolicies, environment) {
    const filteredPolicies = [];
    userPolicies.forEach(function(policy) {
        // keep in the policy what belongs to the environment
        const filteredPolicySettings = [];
        policy.settings.forEach(function(policySetting) {
            const filteredProtectedResources = _.filter(policySetting.protectedResources,
                function(protectedResource) {
                    const resource = systemSecurityData.dictionary.findProtectedResourceByName(protectedResource.resource);
                    return systemSecurityData.resourceTypes.find(resource.type).env.indexOf(environment) !== -1;
                });
            if (filteredProtectedResources.length > 0) {
                const filteredPolicySetting = _.assign({}, policySetting);
                filteredPolicySetting.protectedResources = filteredProtectedResources;
                filteredPolicySettings.push(filteredPolicySetting);
            }
        });
        if (filteredPolicySettings.length > 0) {
            const filteredPolicy = _.assign({}, policy);
            filteredPolicy.settings = filteredPolicySettings;
            filteredPolicies.push(filteredPolicy);
        }
    });
    return filteredPolicies;
}

/**
 *  load user policy data
 *
 *  @returns <promise> that will return the protected resources for the user's security policy
 */
function findUserPolicyData(user) {

    if (!user.permissionRoleCode || user.isTenantAdmin()) {
        logger.warn('Security deactivated for %b', user.display);
        return Promise.resolve([]);
    }

    try {

        return findRole(user)
            .then(generateRolePolicies)
            .catch(function(e) {
                logger.error(user.display + ': **** INVALID SECURITY POLICY ****');
                e.message += '- Invalid security policy for user ' + user.display;
                throw (e);
            });
    } catch (e) {
        logger.error(user.display + ': **** INVALID SECURITY POLICY ****');
        // what do we do if the policy is messed up?
        e.message += '- Invalid security policy for user ' + user.display;
        throw (e);
    }
}


/**
 *  get the policies and their protected resource configuration s for the setting define in the role policy configuration.
 *
 *  @param <object> userRole is an object containing the policies and protected resource settings.
 *  @returns <promise> that will return the protected resources and their configuration for the user's security policy
 */

function generateRolePolicies(userRole) {
    const userPolicies = [];
    userPolicies.description = userRole.description;
    systemSecurityData.policies.forEach(function(policyDefinition) {

        const rolePolicy = _.find(userRole.policies, { name: policyDefinition.name });
        let settings;
        if (rolePolicy && rolePolicy.settings.length) {
            settings = collectRolePolicySettingDefinitions(rolePolicy.settings, policyDefinition);
        }


        // otherwise the default settings of that policy if any
        else if (policyDefinition.defaultSetting) {
            settings = collectRolePolicySettingDefinitions([policyDefinition.defaultSetting], policyDefinition);
        }

        // add all policies selected for the role
        if (settings && settings.length) {
            userPolicies.push({
                name: policyDefinition.name,
                settings: settings
            });
        }
        // otherwise the protected resource will naturally default to their default value

    });
    return userPolicies;
}

/**
 * a policy of a role might have multiple settings checked.
 * 
 * Collect the policy definition with its protected resources and their configuration for those role policy settings.
 * 
 * @returns {array} of policies with their protected resources
 */
function collectRolePolicySettingDefinitions(rolePolicySettings, policyDefinition) {
    return _.map(rolePolicySettings, function(setting) {
        let policySettingConfiguration;
        // setting can be an object with value and params
        if (_.isObject(setting)) {
            policySettingConfiguration = _.find(policyDefinition.settings, { setting: setting.value });
        } else {
            policySettingConfiguration = _.find(policyDefinition.settings, { setting: setting });
        }
        if (!policySettingConfiguration) {
            throw new Error('Setting [' + JSON.stringify(setting) + '] does NOT exist for policy [' + policyDefinition.name + ']');
        }
        // use the params provided in the policy setting if any
        if (setting.params) {
            const c = _.assign({}, policySettingConfiguration);
            c.params = setting.params;
            return c;
        }
        return policySettingConfiguration;
    });
}



