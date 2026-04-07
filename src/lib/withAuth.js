'use strict'

const validateAppToken = require('./validateAppToken')

const withAuth = (roles, handler) => async (request, context) => {
  const token = request.headers.get('Authorization')
  try {
    await validateAppToken(token, { role: roles })
  } catch (error) {
    return { status: 401, jsonBody: { error: error.message } }
  }
  return handler(request, context)
}

module.exports = withAuth
