const jwt = require('jsonwebtoken');
const { SECRET_KEY } = require('../config');
const ExpressError = require('../expressError');

/** Middleware: Requires user is logged in. */
function ensureLoggedIn(req, res, next) {
  try {
    const tokenStr = req.headers.authorization;
    const token = jwt.verify(tokenStr, SECRET_KEY);
    req.user = token;
    return next();
  } catch (err) {
    return next(new ExpressError("Unauthorized", 401));
  }
}

/** Middleware: Requires correct user or admin. */
function ensureCorrectUserOrAdmin(req, res, next) {
  try {
    const tokenStr = req.headers.authorization;
    const token = jwt.verify(tokenStr, SECRET_KEY);
    req.user = token;

    if (req.user.username === req.params.username || req.user.isAdmin) {
      return next();
    } else {
      throw new ExpressError("Unauthorized", 401);
    }
  } catch (err) {
    return next(new ExpressError("Unauthorized", 401));
  }
}

/** Middleware: Authenticates JWT token */
function authenticateJWT(req, res, next) {
  try {
    const tokenStr = req.headers.authorization.split(" ")[1]; // Bearer TOKEN
    const payload = jwt.verify(tokenStr, SECRET_KEY);
    req.user = payload; // Store the payload in req.user
    return next();
  } catch (err) {
    return next(new ExpressError("Unauthorized", 401));
  }
}

module.exports = { ensureLoggedIn, ensureCorrectUserOrAdmin, authenticateJWT };
