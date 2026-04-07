const { createRemoteJWKSet, jwtVerify } = require('jose')

let JWKS
const getJWKS = () => {
  if (!JWKS) {
    JWKS = createRemoteJWKSet(
      new URL(`https://login.microsoftonline.com/${process.env.tenantId}/discovery/keys`)
    )
  }
  return JWKS
}

const toLower = (arr) => arr.map(r => r.toLowerCase())

const validateRoles = (tokenRoles = [], requiredRoles = []) => {
  if (!requiredRoles.length || !tokenRoles.length) return false
  return toLower(tokenRoles).some(r => toLower(requiredRoles).includes(r))
}

const validateAppToken = async (token, options) => {
  if (!token || typeof token !== 'string') throw new Error('Unauthorized: missing token')
  if (!options?.role) throw new Error('Unauthorized: missing required roles config')

  token = token.replace('Bearer ', '')

  try {
    const { payload } = await jwtVerify(token, getJWKS(), {
      issuer: [
        `https://sts.windows.net/${process.env.tenantId}/`,
        `https://login.microsoftonline.com/${process.env.tenantId}/v2.0`
      ],
      audience: process.env.audience,
    })

    if (!validateRoles(payload.roles, options.role)) {
      throw new Error('Unauthorized: insufficient roles')
    }

    return true
  } catch (error) {
    throw new Error(`Unauthorized: ${error.message}`)
  }
}

module.exports = validateAppToken
