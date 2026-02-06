/**
 * Active Directory Remove User from Group Action
 *
 * Removes a user from a group in on-premise Active Directory using LDAP/LDAPS.
 */

import { Client } from 'ldapts';
import { getBaseURL } from '@sgnl-actions/utils';

/**
 * Helper function to remove a user from a group in Active Directory
 * @param {string} userDN - Distinguished Name of the user
 * @param {string} groupDN - Distinguished Name of the group
 * @param {Client} client - Bound ldapts Client instance
 * @returns {Promise<{success: boolean}>}
 */
async function removeUserFromGroup(userDN, groupDN, client) {
  await client.modify(groupDN, [
    {
      operation: 'delete',
      modification: {
        member: [userDN]
      }
    }
  ]);

  return { success: true };
}

export default {
  /**
   * Main execution handler - removes a user from a group in on-premise Active Directory
   * @param {Object} params - Job input parameters
   * @param {string} params.userDN - Distinguished Name of the user
   * @param {string} params.groupDN - Distinguished Name of the group
   * @param {string} [params.address] - Optional LDAP server URL override
   * @param {Object} context - Execution context with env, secrets, outputs
   * @param {string} context.environment.ADDRESS - Default LDAP server URL
   * @param {string} context.secrets.LDAP_BIND_DN - Bind DN for LDAP authentication
   * @param {string} context.secrets.LDAP_BIND_PASSWORD - Bind password for LDAP authentication
   * @param {string} [context.environment.TLS_SKIP_VERIFY] - Set to 'true' to skip TLS certificate verification
   * @returns {Object} Job results
   */
  invoke: async (params, context) => {
    console.log('Starting Active Directory remove user from group operation');

    const { userDN, groupDN, dry_run = false } = params;

    if (dry_run) {
      console.log('DRY RUN: No changes will be made to Active Directory');
      return {
        status: 'dry_run_completed',
        userDN,
        groupDN,
        removed: false
      };
    }

    // Get LDAP server URL using shared utility
    const address = getBaseURL(params, context);

    // Get bind credentials from secrets
    const bindDN = context.secrets.LDAP_BIND_DN;
    const bindPassword = context.secrets.LDAP_BIND_PASSWORD;

    if (!bindDN || !bindPassword) {
      throw new Error('Missing LDAP bind credentials. Provide LDAP_BIND_DN and LDAP_BIND_PASSWORD in secrets.');
    }

    // Build TLS options
    const tlsOptions = {};
    if (context.environment?.TLS_SKIP_VERIFY === 'true') {
      tlsOptions.rejectUnauthorized = false;
    }

    const client = new Client({
      url: address,
      tlsOptions
    });

    try {
      console.log(`Binding to LDAP server at ${address}`);
      await client.bind(bindDN, bindPassword);

      console.log(`Removing user ${userDN} from group ${groupDN}`);
      await removeUserFromGroup(userDN, groupDN, client);

      console.log(`Successfully removed user ${userDN} from group ${groupDN}`);
      return {
        status: 'success',
        userDN,
        groupDN,
        removed: true,
        address
      };
    } catch (error) {
      // LDAP error code 16: NO_SUCH_ATTRIBUTE - user is not a member
      if (error.code === 16) {
        console.log(`User ${userDN} is not a member of group ${groupDN}`);
        return {
          status: 'success',
          userDN,
          groupDN,
          removed: false,
          message: 'User is not a member of the group',
          address
        };
      }

      console.error(`Error removing user from group: ${error.message}`);
      throw error;
    } finally {
      await client.unbind();
    }
  },

  /**
   * Error recovery handler - framework handles retries by default
   * @param {Object} params - Original params plus error information
   * @param {Object} _context - Execution context
   */
  error: async (params, _context) => {
    const { error, userDN, groupDN } = params;
    console.error(`Failed to remove user ${userDN} from group ${groupDN}: ${error.message}`);

    const errorMessage = error.message.toLowerCase();

    // Authentication errors (fatal - don't retry)
    if (errorMessage.includes('invalid credentials') ||
        errorMessage.includes('authentication') ||
        errorMessage.includes('bind failed')) {
      console.error('Authentication failed - check LDAP_BIND_DN and LDAP_BIND_PASSWORD');
      throw new Error(`LDAP authentication failed: ${error.message}`);
    }

    // Connection errors (retryable)
    if (errorMessage.includes('connection') ||
        errorMessage.includes('timeout') ||
        errorMessage.includes('econnrefused')) {
      console.error('Connection error - may be transient, framework will retry');
      throw error;
    }

    // Not found (fatal - don't retry)
    if (errorMessage.includes('not found') ||
        errorMessage.includes('no such object')) {
      console.error('User or group not found - check userDN and groupDN');
      throw new Error(`Resource not found: ${error.message}`);
    }

    // Insufficient permissions (fatal - don't retry)
    if (errorMessage.includes('insufficient access') ||
        errorMessage.includes('permission denied')) {
      console.error('Insufficient permissions - check service account privileges');
      throw new Error(`Insufficient LDAP permissions: ${error.message}`);
    }

    // Unknown error - re-throw for framework retry
    console.error('Unknown error occurred, allowing framework to retry');
    throw error;
  },

  /**
   * Graceful shutdown handler - performs cleanup
   * @param {Object} params - Original params plus halt reason
   * @param {Object} _context - Execution context
   * @returns {Object} Cleanup results
   */
  halt: async (params, _context) => {
    const { reason, userDN, groupDN } = params;
    console.log(`Active Directory remove user from group operation halted: ${reason}`);

    return {
      status: 'halted',
      userDN: userDN || 'unknown',
      groupDN: groupDN || 'unknown',
      reason,
      halted_at: new Date().toISOString()
    };
  }
};
