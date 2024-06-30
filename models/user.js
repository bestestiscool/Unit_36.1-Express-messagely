const bcrypt = require('bcrypt');
const db = require('../db');
/** User class for message.ly */

/** User of the site. */

class User {

  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */
  static async register({ username, password, first_name, last_name, phone }) {
    const hashPassword = await bcrypt.hash(password, 10);
    const result = await db.query(
      `INSERT INTO users (username, password, first_name, last_name, phone, join_at) 
       VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP) 
       RETURNING username, first_name, last_name, phone, join_at`,
      [username, hashPassword, first_name, last_name, phone]
    );

    return result.rows[0];
  }

  /** Authenticate: is this username/password valid? Returns boolean. */
  static async authenticate(username, password) {
    const result = await db.query(
      `SELECT username, password FROM users WHERE username = $1`,
      [username]
    );

    if (result.rows.length === 0) {
      throw new Error(`No such username: ${username}`);
    }

    const user = result.rows[0];
    const isValid = await bcrypt.compare(password, user.password);

    if (!isValid) {
      throw new Error('Invalid username/password', 400);
    }

    return true;
  }

  /** Update last_login_at for user */
  static async updateLoginTimestamp(username) {
    const result = await db.query(
      `UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE username = $1 RETURNING username, last_login_at`,
      [username]
    );

    if (result.rows.length === 0) {
      throw new ExpressError(`No such username: ${username}`, 404);
    }

    return result.rows[0];
  }


  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */
  static async all() {
    const result = await db.query(
      `SELECT username, first_name, last_name, phone FROM users`
    );

    return result.rows;
  }

  /** Get: get user by username
   *
   * returns {username, first_name, last_name, phone, join_at, last_login_at} */
  static async get(username) {
    const result = await db.query(
      `SELECT username, first_name, last_name, phone, join_at, last_login_at 
       FROM users WHERE username = $1`,
      [username]
    );

    if (result.rows.length === 0) {
      throw new Error(`No such username: ${username}`);
    }

    return result.rows[0];
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */
  static async messagesFrom(username) {
    const result = await db.query(
      `SELECT m.id, 
              m.to_username AS to_user, 
              m.body, 
              m.sent_at, 
              m.read_at,
              u.username, 
              u.first_name, 
              u.last_name, 
              u.phone
       FROM messages AS m
       JOIN users AS u ON m.to_username = u.username
       WHERE m.from_username = $1`,
      [username]
    );

    return result.rows.map(row => ({
      id: row.id,
      to_user: {
        username: row.to_user,
        first_name: row.first_name,
        last_name: row.last_name,
        phone: row.phone
      },
      body: row.body,
      sent_at: row.sent_at,
      read_at: row.read_at
    }));
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */
  static async messagesTo(username) {
    const result = await db.query(
      `SELECT m.id, 
              m.from_username AS from_user, 
              m.body, 
              m.sent_at, 
              m.read_at,
              u.username, 
              u.first_name, 
              u.last_name, 
              u.phone
       FROM messages AS m
       JOIN users AS u ON m.from_username = u.username
       WHERE m.to_username = $1`,
      [username]
    );

    return result.rows.map(row => ({
      id: row.id,
      from_user: {
        username: row.from_user,
        first_name: row.first_name,
        last_name: row.last_name,
        phone: row.phone
      },
      body: row.body,
      sent_at: row.sent_at,
      read_at: row.read_at
    }));
  }
}

module.exports = User;