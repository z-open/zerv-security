
'strict mode';

const Promise = require('promise'),
    zlog = require('zimit-zlog'),
    _ = require('lodash');

const UUID = require('uuid');

const securityService = require('./security.service');

let zervCore;
_.forIn(require.cache, function (required) {
    if (required.exports && required.exports.apiRouter) {
        zervCore = required.exports;
        return false;
    }
});
if (!zervCore) {
    zervCore = require('zerv-core');
}

let zervSync;
_.forIn(require.cache, function (required) {
    if (required.exports && required.exports.notifyCreation) {
        zervSync = required.exports;
        return false;
    }
});
if (!zervSync) {
    zervSync = require('zerv-sync');
}


let zervSecurity;
_.forIn(require.cache, function (required) {
    if (required.exports && required.exports.notifySecurityUpdate) {
        zervSecurity = required.exports;
        return false;
    }
});
// prevent creating another instance of this module
if (zervSecurity) {
    module.exports = zervSecurity;
    return;
}


UUID.generate = UUID.v4;



const logger = zlog.getLogger('zerv/security');

const security = {
    notifyPolicyUpdate,
    applyResourcePolicy: securityService.applyResourcePolicy,
    initializePolicies
};

zervCore.addModule('Security', security);


module.exports = security;






////////////////// PUBLIC //////////////////////

/**
 * load the security policy configuration to apply application wide 
 * @param {Object} securityConfiguration:
 * 
 */function initializePolicies(securityConfiguraton) {
    try {
        securityService.load(securityConfiguraton);
        zervSync
            .publish('all.security-policies.sync', fetchAllPolicyDefinitions, 'NONE')
            .publish('security.sync', securityConfig, 'SECURITY_CONFIG_DATA', getSecuritySyncOptions());
    }
    catch (e) {
        logger.fatal('Server shutdown.');
        process.exit(1);
    }

}



/**
 * when a user is modified (the user security role is modified), or when a security role config is modified, the front end must be notified to apply the new policy settings.
 * 
 */
async function notifyPolicyUpdate(user) {
    logger.debug('Broadcast SecurityPolicy update for user %b.', user.display || user.id);
    zervSync.notifyUpdate(user.tenantId, 'SECURITY_CONFIG_DATA', await securityService.collectClientUserPolicy(user));
}


//////////////////////////////
function fetchAllPolicyDefinitions(tenantId, user, params) {
    return Promise.resolve(
        _.sortBy(
            _.map(securityService.getSystemSecurityConfiguration().policies, formatPolicyConfig),
            'name')
    );
}

/**
 * policies are hard coded config, this makes them syncable
 */
function formatPolicyConfig(policy) {
    // the policy needs to be reformatted for now as params are tricky.
    return _.assign(
        { id: UUID.generate(), revision: 0 },
        {
            name: policy.name,
            description: policy.description
        },
        {
            settings: _.map(policy.settings, function (setting) {
                return {
                    notes: setting.notes,
                    value: setting.setting,
                    params: setting.parameters // should be params after code fix
                };
            })
        });
}




function securityConfig(tenantId, user, params) {
    return securityService.findUserByTenantIdAndId(user.tenantId, user.id).then(securityService.collectClientUserPolicy);
}


function getSecuritySyncOptions() {
    return {
        init: function (tenantId, user, params) {
            // the client does not pass the current userId. safer here.
            // this is necessary to make sure that data notified are relevant to the subscription.
            params.userId = user.id;
        }
    };
}

