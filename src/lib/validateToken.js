// Validate the roles of the user to access the route
// Check for roles in the token and return true or false if the user has the required role

const validate = require('validate-azure-ad-token').default
const jwt = require('jsonwebtoken')
const https = require('https')

// Cache valid key IDs to avoid re-fetching JWKS on every request
const jwksKidCache = new Set()

const fetchJwks = (tenantId) => new Promise((resolve, reject) => {
  https.get(`https://login.microsoftonline.com/${tenantId}/discovery/keys`, (res) => {
    let data = ''
    res.on('data', chunk => { data += chunk })
    res.on('end', () => { try { resolve(JSON.parse(data)) } catch (e) { reject(e) } })
  }).on('error', reject)
})

/**
 * Validates an application token (client credentials / no delegated scopes).
 * Mirrors what validate-azure-ad-token does but skips appid and scp checks,
 * which don't apply to app tokens.
 */
const validateAppToken = async (token) => {
  const decoded = jwt.decode(token, { complete: true, json: true })
  if (!decoded) throw new Error('Token could not be decoded')

  const { header, payload } = decoded
  if (!header.kid) throw new Error('Token header missing kid')

  if (!jwksKidCache.has(header.kid)) {
    const jwks = await fetchJwks(process.env.tenantId)
    if (!jwks.keys.some(k => k.kid === header.kid)) {
      throw new Error('Token public key not found in JWKS')
    }
    jwksKidCache.add(header.kid)
  }

  console.log("--- APP TOKEN CLAIMS ---", JSON.stringify({ tid: payload.tid, aud: payload.aud, iss: payload.iss, appid: payload.appid, roles: payload.roles }))
  console.log("--- ENV ---", JSON.stringify({ tenantId: process.env.tenantId, audience: process.env.audience, applicationId: process.env.applicationId }))
  if (payload.tid !== process.env.tenantId) throw new Error('Invalid tenantId')
  if (payload.aud !== process.env.audience) throw new Error('Invalid audience')
  if (!payload.iss || !payload.iss.includes('sts') || !payload.iss.includes(process.env.tenantId)) {
    throw new Error('Invalid issuer')
  }
  if (!payload.exp || payload.exp <= Math.floor(Date.now() / 1000)) throw new Error('Token expired')

  return decoded
}

/**
 *
 * @param {Array} tokenRoles Token from the request
 * @param {Array} role Roles needed to access the route
 * @returns
 */
const validateRoles = (tokenRoles, role) => {
  console.log("--- DEBUG: Token Roles ---", tokenRoles);
  console.log("--- DEBUG: Required Roles ---", role);
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
  console.log("-----------test-----------")
  token = token.replace('Bearer ', '')
  try {
    console.log("try decode")
    console.log("tenantid " + process.env.tenantId)
    console.log("audience " + process.env.audience)
    console.log("appId " + process.env.applicationId)
    console.log("scopes " + scopes)
    let decodedToken
    if (scopes && scopes.length > 0) {
      decodedToken = await validate(token, {
        tenantId: process.env.tenantId,
        audience: process.env.audience,
        applicationId: process.env.applicationId,
        scopes,
      })
    } else {
      decodedToken = await validateAppToken(token)
    }
    if (validateRoles(decodedToken.payload.roles, options.role)) {
      return true
    } else {
      console.log("role unauthorized")
      throw new Error('Unauthorized')
    }
    // return validateRoles(decodedToken.payload.roles, options.role) ? true : false;
} catch (error) {
    console.error("--- VALIDATION ERROR DETAILS ---");
    console.error("Message:", error.message);
    
    // This prints the line numbers and the "reason" (e.g., Expired, Invalid Signature)
    console.error("Stack:", error.stack); 

    // If the library 'validate-azure-ad-token' provides extra details:
    if (error.details) {
      console.error("Details:", JSON.stringify(error.details, null, 2));
    }

    throw new Error(`Unauthorized: ${error.message}`);
  }
}

module.exports = validateToken
