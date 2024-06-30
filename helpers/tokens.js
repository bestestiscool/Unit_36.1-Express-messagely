const jwt = require('jsonwebtoken');
const { SECRET_KEY } = require('../config');

/** Return signed JWT from user data. */
function createToken(username) {
  const payload = { username };
  return jwt.sign(payload, SECRET_KEY);
}

module.exports = { createToken };
