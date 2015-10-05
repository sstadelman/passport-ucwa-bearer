/**
 * Module dependencies.
 */
var passport = require('passport-strategy')
  , util = require('util')
//   , q = require('q')
  , asyncRequest = require('request-promise')
  , ucwa = require('./ucwa');


/**
 * `BasicStrategy` constructor.
 *
 * The HTTP Basic authentication strategy authenticates requests based on
 * userid and password credentials contained in the `Authorization` header
 * field.
 *
 * Applications must supply a `verify` callback which accepts `userid` and
 * `password` credentials, and then calls the `done` callback supplying a
 * `user`, which should be set to `false` if the credentials are not valid.
 * If an exception occured, `err` should be set.
 *
 * Optionally, `options` can be used to change the authentication realm.
 *
 * Options:
 *   - `realm`  authentication realm, defaults to "Users"
 *
 * Examples:
 *
 *     passport.use(new BasicStrategy(
 *       function(userid, password, done) {
 *         User.findOne({ username: userid, password: password }, function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * For further details on HTTP Basic authentication, refer to [RFC 2617: HTTP Authentication: Basic and Digest Access Authentication](http://tools.ietf.org/html/rfc2617)
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
	console.log('options = ' + util.inspect(options) + ', verify = ' + util.inspect(verify));
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }
  if (!verify) throw new Error('HTTP Basic authentication strategy requires a verify function');
  
  passport.Strategy.call(this);
  this.name = 'ucwa';
  this._verify = verify;
  this._realm = options.realm || 'Users';
  this._passReqToCallback = options.passReqToCallback;
  this._user = {}
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on the contents of a HTTP Basic authorization
 * header.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req) {
	
	req['user'] = {};
	var self = this;

	var authorization = req.headers['authorization'];
	if (!authorization) { return this.fail(this._challenge()); }

	var parts = authorization.split(' ')
	if (parts.length < 2) { return this.fail(400); }

	var scheme = parts[0]
	, credentials = new Buffer(parts[1], 'base64').toString().split(':');

	if (!/Basic/i.test(scheme)) { return this.fail(this._challenge()); }
	if (credentials.length < 2) { return this.fail(400); }

// 	self._user.userid = credentials[0];
// 	self._user.password = credentials[1];
	req.user.username = credentials[0];
	req.user.password = credentials[1];
	
// 	if (!self._user.userid || !self._user.password) {
	if (!req.user.username || !req.user.password) {
		return this.fail(this._challenge());
	}

	
// 	self._user.email = req.body.email;
	req.user.email = req.body.email;

	function verified(err, user) {
	if (err) { return self.error(err); }
	if (!user) { return self.fail(self._challenge()); }
		self.success(user);
	}
	console.log('FLAG 1');
	// lync.setup(self._user.email, self._user.userid, self._user.password)
	ucwa.setup(req.user.email, req.user.username, req.user.password)
	.then(function(ucwa_user) {
		console.log('FLAG 2');
		req.user.urls = ucwa_user.urls
		req.user.token  = ucwa_user.token;
		if (self._passReqToCallback) {
			self._verify(req, req.user.username, req.user.password, verified);
		} else {
			self._verify(req.user.username, req.user.password, verified);
		}
	})
	.catch(function(err) {
		console.log('here was an error: ' + err);
	});
}



/**
 * Authentication challenge.
 *
 * @api private
 */
Strategy.prototype._challenge = function() {
  return 'Basic realm="' + this._realm + '"';
}


/**
 * Expose `UcwaStrategy`.
 */ 
module.exports = Strategy;
