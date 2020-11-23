// backend
if (typeof require !== 'undefined') {
    _ = require('lodash');
    module.exports = UserPolicy;
} else {
    window.UserPolicy = UserPolicy;
}

/**
 *
 *  User Policy object contains the mapping to all objects related to security.
 *
 *  It gives access to all protected resources. All protected resources are mapped to their implementation.
 *
 *  Protected resource object provide 2 methods:
 *
 *  - calculateSetting: calculates and returns what would be setting value for the resource based on the policies configuration. calculation might depends on condition specific to a policy.
 *
 *  - Apply: Run the implementation as defined in the resource type.
 *
 *  @param <object>: Security data contains the definition of the policy
 *  @param <fun> getPolicyConditionFactory is a function returning the condition function to execute
 *  @param <func> getPolicyImplementationFactory is a function returning the implementation of the resouce type
 *
 */
function UserPolicy(securityData, getPolicyConditionFactory, getResourceTypeFactory) {
    const protectedResourceList = compileSecurityData(securityData);

    this.getProtectedResourcesByTarget = function(groupName) {
        return _.filter(protectedResourceList, {target: groupName});
    };

    this.getProtectedResourceByLocator = function(locator) {
        // console.log(protectedResourceList);
        const protectedResource = _.find(protectedResourceList, function(r) {
            return r.resource.locator === locator;
        });
        if (!protectedResource) {
            throw new Error('Protected resource [' + locator + '] undefined');
        }
        return protectedResource;
    };


    /**
      * This returns the protected resource list.
      * Each resource is mapped to their implementation.
      *
      */
    function compileSecurityData(securityData) {
        const protectedResourceMap = buildProtectedResources(
            securityData.dictionary || [],
            securityData.resourceTypes || []
        );
        addProtectedResourcePreferences(
            securityData.policies || [],
            protectedResourceMap
        );

        return _.values(protectedResourceMap);
    }


    function buildProtectedResources(dictionary, resourceTypes) {
        const resourceMap = {};
        dictionary.forEach((resourceData) => {
            const resource = _.assign({}, resourceData);
            resource.type = _.find(resourceTypes, {name: resource.type});
            resource.defaultSetting = buildResourceSettingObject(resource, resource.defaultSetting, resource.params);
            resourceMap[resource.name] = buildProtectedResourceObject(resource); ;
        });
        return resourceMap;
    }

    /**
     *  format the security data
     *
     *  @returns a list of protected resources plugged to proper policy implementation
     *
     */
    function addProtectedResourcePreferences(policies, protectedResources) {
        policies.forEach((policy) => {
            policy.settings.forEach((policySettingConfig) => {
                const policySetting = _.assign({}, policySettingConfig);
                policySetting.checkIfEnabled = getPolicyConditionImplementation(policySetting);
                policySetting.policy = policy;

                policySetting.protectedResources.forEach((policyResourceConfig) => {
                    try {
                        addPolicyResourceSettingToProtectedResource(
                            policyResourceConfig,
                            protectedResources[policyResourceConfig.resource],
                            policySetting);
                    } catch (e) {
                        e.message += ' - Issue in with policy setting [' + policySetting.setting +
                            ']';
                        throw e;
                    }
                });
            });
        });
    }

    /**
     *  A single protectedResource might have different possible settings. Policy defines those settings in the protected resource list.
     *
     */
    function addPolicyResourceSettingToProtectedResource(policyResourceConfig, protectedResource, policySetting) {
        if (!protectedResource) {
            throw new Error('Resource [' + policyResourceConfig.resource + '] does not exist in dictionary');
        }
        // Replace string representations by the correct object
        const resourceConfig = _.assign({}, policyResourceConfig);
        resourceConfig.policySetting = policySetting;
        resourceConfig.resource = protectedResource.resource;
        resourceConfig.setting = buildResourceSettingObject(protectedResource.resource, resourceConfig.setting, resourceConfig.params);
        // let's that specific policy config to the protected resource
        protectedResource.settings.push(resourceConfig);
    }


    /**
    * a resource might be declared in multiple policies.
    *
    * In order to determine which setting must be applied to the protected resource, check which policy is enabled for this resource otherwise use the resource default setting.
    *
    * Manage when multiple policy resource setting might conflict using the resource type priority parameter.
    *
    * @return the resource setting otherwise null if there is no policy valid for this resource.
    *
    */
    function computeResourceSetting(protectedResource, contextParams) {
        let finalSetting;
        const logs = [];
        logs.push('------ Determining Setting for Resource [' + protectedResource.resource.name + '] ------');
        // find out which setting applies for this protectedResource.
        if (!protectedResource.settings) {
            logs.push('No policy covered this resource. Using default resource setting: ' + JSON.stringify(protectedResource.resource.defaultSetting));
        } else {
            protectedResource.settings.forEach(
                function(resourceConfig) {
                    let setting;
                    if (resourceConfig.policySetting.checkIfEnabled(contextParams)) {
                        setting = resourceConfig.setting;
                        logs.push('Policy [' + resourceConfig.policySetting.policy.name + '] ENABLED for setting [' + resourceConfig.policySetting.setting + ']' + JSON.stringify(resourceConfig.policySetting.params) + ': ' + JSON.stringify(setting));
                    } else {
                        logs.push('Policy [' + resourceConfig.policySetting.policy.name + '] DISABLED for setting [' + resourceConfig.policySetting.setting + ']' + JSON.stringify(resourceConfig.policySetting.params) + ': Resource not impacted.');
                    }
                    // if the policy condition is valid, we get setting for this protected element
                    if (setting && (!finalSetting || finalSetting.priority > setting.priority)) {
                        finalSetting = setting;
                    }
                });
        }
        // if there is no setting set by any policy, the default setting is the one in the dictionary.
        if (!finalSetting) {
            finalSetting = protectedResource.resource.defaultSetting;
            logs.push('Using default Resource Setting: ' + JSON.stringify(finalSetting));
        } else {
            logs.push('Resource Setting Result: ' + JSON.stringify(finalSetting));
        }
        // console.log(logs.join('\n'));

        // we should always get a setting...    at least the default one.
        return finalSetting;
    }

    /**
       *
       * this build the resource setting object which contains the data defined in a policy to apply to a resource.
       */
    function buildResourceSettingObject(resource, setting, params) {
        const settingObject = _.find(resource.type.settings, {value: setting});
        return _.assign({}, params, settingObject);
    }


    /**
    * build the protected resource object that encapsulates behavior
    * It can determine the current setting and apply to its resource.
    *
    */
    function buildProtectedResourceObject(resource) {
        // var resource = _.find(dictionary, { name: resourceName });
        // if (!resource) {
        //     throw new Error('Resource [' + resourceName + '] does not exist in dictionary');
        // }

        const implementation = getResourceImplementation(resource.type);

        const protectedResource = {
            // resource of the dictionary with its type object.
            resource: resource,
            // each setting of a policy might provide different resource settings.
            settings: [],
            // this calculate what should be the setting for this resource (need to compute all the settings define in each policies mentioning this resource)
            // ContextParams might be passed to allow the calculation (calculation might be based on condition requiring external params)
            calculateSetting: function(contextParams) {
                return computeResourceSetting(protectedResource, contextParams);
            },
            // this is the function to apply to the resource. each resource type defines of different implementation. ex: htmlElement hide/show things, Input enable/disable....
            apply: implementation.apply,
            // this is to group the protected resources... some are related to the DOM, some to uiRouter, some to api, etc.
            target: implementation.target
        };
        return protectedResource;
    }


    /**
      * Find the condition code in a factory if a condition is provided.
      * handle error message.
      *
      * @param <object> policySetting object might have a condition
      *
      * @returns the condition function
      */
    function getPolicyConditionImplementation(policySetting) {
        // if there is a policy with no condition, so it is enabled.
        if (!policySetting.condition) {
            return function() {
                return true;
            };
        }

        try {
            const period = policySetting.condition.indexOf('.');
            if (period === -1) {
                throw new Error('No security name defined');
            }
            const factoryName = policySetting.condition.substring(0, period);
            const conditionGroup = getPolicyConditionFactory(factoryName);
            const conditionName = policySetting.condition.substring(period + 1);
            const conditionFn = conditionGroup[conditionName];
            if (!conditionFn) {
                throw new Error('No condition implementation [' + conditionName + '] in [' + factoryName + ']');
            }
            // contextParams will be passed when the protectedResource apply method is called.
            return function(contextParams) {
                try {
                    return conditionFn(policySetting.params, contextParams);
                } catch (e) {
                    e.message += ' - make sure the context param object is passed when calling the protected resource apply method';
                    throw e;
                }
            };
        } catch (e) {
            // this should never happen...but if it does...we should send user to another screen ex: Issue reported..and not allow the app to work at all.
            e.message += '- Unknown security condition [' + policySetting.condition + '] for policy setting [' + policySetting.setting + ']';
            throw e;
        }
    }


    /**
     *  This function returns the implementation of the resource type.
     *
     *  This object has an apply method that will apply the setting to the physical resource
     *  ex: for a form, could apply 'disabled'
     *
     *  {
        target: 'dom',
        apply: function applyToHtmlElement(element, setting) {
            if (setting.value === 'disabled') {
                element.prop('disabled', true);
            } else {
                element.prop('disabled', false);
            }
        }
     *
     *  @returns <object>
     *
    };
     */

    function getResourceImplementation(resourceType) {
        try {
            return getResourceTypeFactory(resourceType);
        } catch (e) {
            e.message += ' - Unknown policy implementation for resource type [' + resourceType + ']';
            // this should never happen...but if it does...we should send user to another screen ex: Issue reported..and not allow the app to work at all.
            throw e;
        }
    }
}
