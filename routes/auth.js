const express = require('express');
const router = express.Router();
const User = require('../models/user');
const { createToken } = require('../helpers/tokens');
const ExpressError = require('../expressError');


/** POST /login - login: {username, password} => {token} */
router.post('/login', async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const isValid = await User.authenticate(username, password);

    if (isValid) {
      const token = createToken(username);
      await User.updateLoginTimestamp(username);
      return res.json({ token });
    } else {
      throw new ExpressError('Invalid username/password', 400);
    }
  } catch (err) {
    return next(err);
  }
});

/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 * Make sure to update their last-login!
 */
router.post('/register', async (req, res, next) => {
  try {
    const { username, password, first_name, last_name, phone } = req.body;
    const newUser = await User.register({ username, password, first_name, last_name, phone });

    const token = createToken(newUser.username);
    await User.updateLoginTimestamp(newUser.username);
    return res.json({ token });
  } catch (err) {
    return next(err);
  }
});

module.exports = router;
