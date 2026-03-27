// Validate the roles of the user to access the route
// Check for roles in the token and return true or false if the user has the required role

const validate = require('validate-azure-ad-token').default

/**
 *
 * @param {Array} tokenRoles Token from the request
 * @param {Array} role Roles needed to access the route
 * @returns
 */
const validateRoles = (tokenRoles, role) => {
  if (!role) {
    return false
  }
  if (!tokenRoles) {
    return false
  }
  const toLowerCase = (arr) => arr.map((r) => r.toLowerCase())
  // Convert the roles to lowercase
  tokenRoles = toLowerCase(tokenRoles)
  role = toLowerCase(role)
  // Check if the user has the required role.
  const hasRole = tokenRoles.some((r) => role.includes(r))
  return hasRole
}

/**
 *
 * @param {String} token Accesstoken from the request
 * @param {Object} options Options for the token
 * @returns
 */

const validateToken = async (token, options, scopes=['user_impersonation']) => {
  token = token.replace('Bearer ', '')
  try {
    const decodedToken = await validate(token, {
      tenantId: process.env.tenantId,
      audience: process.env.audience,
      applicationId: process.env.applicationId,
      scopes: scopes
    })
    if (validateRoles(decodedToken.payload.roles, options.role)) {
      return true
    } else {
      throw new Error('Unauthorized')
    }
    // return validateRoles(decodedToken.payload.roles, options.role) ? true : false;
  } catch (error) {
    throw new Error('Unauthorized', error)
  }
}

module.exports = validateToken
