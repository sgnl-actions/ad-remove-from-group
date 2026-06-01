/**
 * Active Directory Remove Member from Group Action
 *
 * Removes a member (user or group) from a group in on-premise Active Directory
 * using LDAP/LDAPS. If the member is not in the group, returns success with
 * removed=false.
 */

import { Client, Change, Attribute } from 'ldapts';
import { getBaseURL } from '@sgnl-actions/utils';

/**
 * Escape special characters in LDAP filter values to prevent injection.
 *
 * @param {string} str - The string to escape
 * @returns {string} The escaped string safe for use in LDAP filters
 */
function escapeLDAPFilter(str) {
  return str.replace(/[\\*()\0]/g, (char) => '\\' + char.charCodeAt(0).toString(16).padStart(2, '0'));
}

/**
 * Find a member's Distinguished Name by searching for their sAMAccountName.
 * Matches both user and group objects since sAMAccountName is unique across
 * the domain for both types.
 *
 * @param {Client} client - Bound ldapts Client instance
 * @param {string} baseDN - Base DN to search from
 * @param {string} samAccountName - Member's sAMAccountName
 * @returns {Promise<string>} The member's Distinguished Name
 * @throws {Error} If member not found or multiple members found
 */
async function findMemberDN(client, baseDN, samAccountName) {
  console.log(`Searching for member with sAMAccountName: ${samAccountName}`);

  const escapedSamAccountName = escapeLDAPFilter(samAccountName);
  const { searchEntries } = await client.search(baseDN, {
    scope: 'sub',
    filter: `(&(|(objectClass=user)(objectClass=group))(sAMAccountName=${escapedSamAccountName}))`,
    attributes: ['distinguishedName']
  });

  if (!searchEntries || searchEntries.length === 0) {
    throw new Error(`Member not found with sAMAccountName: ${samAccountName}`);
  }

  if (searchEntries.length > 1) {
    throw new Error(`Multiple members found with sAMAccountName: ${samAccountName}. Expected exactly one.`);
  }

  const memberDN = searchEntries[0].dn;
  console.log(`Found member DN: ${memberDN}`);
  return memberDN;
}

/**
 * Safely disconnect from LDAP server.
 * Errors during unbind are logged but not thrown to avoid masking original errors.
 *
 * @param {Client} client - The ldapts client
 */
async function safeUnbind(client) {
  if (!client) {
    return;
  }
  try {
    await client.unbind();
  } catch (unbindError) {
    console.warn(`Warning: Error during LDAP unbind: ${unbindError.message}`);
  }
}

/**
 * Remove a member from a group in Active Directory by modifying the group's member attribute.
 *
 * @param {string} memberDN - Distinguished Name of the member to remove
 * @param {string} groupDN - Distinguished Name of the group
 * @param {Client} client - Bound ldapts Client instance
 * @returns {Promise<{success: boolean}>}
 */
async function removeMemberFromGroup(memberDN, groupDN, client) {
  await client.modify(groupDN, [
    new Change({
      operation: 'delete',
      modification: new Attribute({
        type: 'member',
        values: [memberDN]
      })
    })
  ]);

  return { success: true };
}

export default {
  /**
   * Main execution handler - removes a member (user or group) from a group in Active Directory.
   *
   * @param {Object} params - Job input parameters
   * @param {string} params.baseDN - Base DN to search for the member
   * @param {string} params.samAccountName - Member's sAMAccountName to lookup
   * @param {string} params.groupDN - Distinguished Name of the group
   * @param {string} [params.address] - Optional LDAP server URL override
   * @param {boolean} [params.dry_run] - If true, validate without making changes
   * @param {Object} context - Execution context with environment and secrets
   * @returns {Object} Job results including status, memberDN, groupDN, and removed flag
   */
  invoke: async (params, context) => {
    console.log('Starting Active Directory remove member from group operation');

    const { baseDN, samAccountName, groupDN, dry_run = false } = params;

    // Validate required parameters
    if (!baseDN) {
      throw new Error('baseDN is required');
    }
    if (!samAccountName) {
      throw new Error('samAccountName is required');
    }
    if (!groupDN) {
      throw new Error('groupDN is required');
    }

    console.log(`Planning to remove member "${samAccountName}" from group "${groupDN}"`);

    // Handle dry run - validate and return without making changes
    if (dry_run) {
      console.log('DRY RUN: No changes will be made to Active Directory');
      return {
        status: 'dry_run_completed',
        baseDN,
        samAccountName,
        memberDN: null,
        userDN: null,
        groupDN,
        removed: false
      };
    }

    // Get LDAP connection details
    const address = getBaseURL(params, context);
    const bindDN = context.secrets.BASIC_USERNAME;
    const bindPassword = context.secrets.BASIC_PASSWORD;

    // Validate required secrets
    if (!bindDN || !bindPassword) {
      throw new Error('Missing LDAP bind credentials. Provide BASIC_USERNAME and BASIC_PASSWORD in secrets.');
    }

    // Configure LDAP client with timeouts
    const clientOptions = {
      url: address,
      timeout: 10000,
      connectTimeout: 10000
    };

    // Configure TLS options for secure connections
    // Only apply TLS options to ldaps:// (encrypted) connections
    // For ldap:// (plain text) connections, TLS options cause connection failures
    if (address.startsWith('ldaps://')) {
      clientOptions.tlsOptions = {
        rejectUnauthorized: context.environment?.TLS_SKIP_VERIFY !== 'true'
      };
    }

    const client = new Client(clientOptions);

    try {
      console.log(`Connecting to LDAP server at ${address}`);
      await client.bind(bindDN, bindPassword);
      console.log('Successfully authenticated to LDAP server');

      // Lookup member DN by sAMAccountName
      const memberDN = await findMemberDN(client, baseDN, samAccountName);

      console.log(`Removing member from group: ${groupDN}`);
      await removeMemberFromGroup(memberDN, groupDN, client);

      console.log(`Successfully removed member "${memberDN}" from group "${groupDN}"`);
      return {
        status: 'success',
        memberDN,
        userDN: memberDN,
        groupDN,
        removed: true,
        address,
        baseDN,
        samAccountName
      };
    } catch (error) {
      // LDAP error codes 16 (NO_SUCH_ATTRIBUTE) and 53 (UNWILLING_TO_PERFORM) - member is not in the group
      if (error.code === 16 || error.code === 53) {
        // Need to get memberDN for the response - it might have been found before error
        let memberDN = 'unknown';
        try {
          memberDN = await findMemberDN(client, baseDN, samAccountName);
        } catch (lookupError) {
          console.warn(`Warning: Could not retrieve member DN for response: ${lookupError.message}`);
        }
        console.log(`Member "${memberDN}" is not a member of group "${groupDN}"`);
        return {
          status: 'success',
          memberDN,
          userDN: memberDN,
          groupDN,
          removed: false,
          message: 'Member is not in the group',
          address,
          baseDN,
          samAccountName
        };
      }

      console.error(`Failed to remove member from group: ${error.message}`);
      throw error;
    } finally {
      await safeUnbind(client);
    }
  },

  /**
   * Error recovery handler - classifies errors and determines retry behavior.
   *
   * @param {Object} params - Original params plus error information
   * @param {Error} params.error - The error that occurred
   * @param {string} params.baseDN - The base DN being searched
   * @param {string} params.samAccountName - The sAMAccountName being looked up
   * @param {string} params.groupDN - The group DN being modified
   * @param {Object} _context - Execution context (unused)
   * @throws {Error} Re-throws with appropriate classification
   */
  error: async (params, _context) => {
    const { error, samAccountName, groupDN } = params;
    console.error(`Error handler invoked for removing "${samAccountName}" from "${groupDN}": ${error.message}`);

    const errorMessage = error.message.toLowerCase();

    // Authentication errors (fatal - don't retry)
    if (errorMessage.includes('invalid credentials') ||
        errorMessage.includes('authentication') ||
        errorMessage.includes('bind failed')) {
      console.error('Authentication failed - check BASIC_USERNAME and BASIC_PASSWORD');
      throw new Error(`LDAP authentication failed: ${error.message}`);
    }

    // Connection errors (retryable - framework will retry)
    if (errorMessage.includes('connection') ||
        errorMessage.includes('timeout') ||
        errorMessage.includes('econnrefused')) {
      console.error('Connection error - may be transient, framework will retry');
      throw error;
    }

    // Member not found (fatal - don't retry)
    if (errorMessage.includes('member not found')) {
      console.error('Member not found - check samAccountName and baseDN');
      throw new Error(`Member not found: ${error.message}`);
    }

    // Multiple members found (fatal - don't retry)
    if (errorMessage.includes('multiple members found')) {
      console.error('Multiple members found - sAMAccountName should be unique');
      throw new Error(`Multiple members found: ${error.message}`);
    }

    // Not found (fatal - don't retry)
    if (errorMessage.includes('not found') ||
        errorMessage.includes('no such object')) {
      console.error('Resource not found - check groupDN');
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
   * Graceful shutdown handler - called when the job is halted.
   *
   * @param {Object} params - Original params plus halt reason
   * @param {string} params.reason - The reason for the halt
   * @param {string} [params.baseDN] - The base DN being searched
   * @param {string} [params.samAccountName] - The sAMAccountName being looked up
   * @param {string} [params.groupDN] - The group DN being modified
   * @param {Object} _context - Execution context (unused)
   * @returns {Object} Cleanup results with halted status
   */
  halt: async (params, _context) => {
    const { reason, baseDN, samAccountName, groupDN } = params;
    console.log(`Active Directory remove member from group operation halted: ${reason}`);

    return {
      status: 'halted',
      baseDN: baseDN || 'unknown',
      samAccountName: samAccountName || 'unknown',
      groupDN: groupDN || 'unknown',
      reason,
      halted_at: new Date().toISOString()
    };
  }
};
