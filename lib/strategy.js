/**
 * Module dependencies.
 */
var passport = require('passport-strategy')
  , util = require('util')
  , asyncRequest = require('request-promise');
  // , ucwa = require('./ucwa');


/**
 * `Ucwa` constructor.
 *
 * The HTTP Basic authentication strategy authenticates requests based on
 * Bearer access_token contained in the `Authorization` header
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
 *		passport.use(new UcwaStrategy({passReqToCallback: true},
 *		function(req, application_href, access_token, done) {
 *			
 *			FindUser(req.user)
 *			.then(function(u) {
 *				done(null, u);
 *			})
 *			.catch(function() {
 *				done(null, false);
 *			})
 *		}));
 *
 * For further details on HTTP Basic authentication, refer to [RFC 2617: HTTP Authentication: Basic and Digest Access Authentication](http://tools.ietf.org/html/rfc2617)
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function UcwaStrategy(options, verify) {
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
util.inherits(UcwaStrategy, passport.Strategy);

/**
 * Authenticate request based on the contents of a HTTP Basic authorization
 * header.
 *
 * @param {Object} req
 * @api protected
 */
UcwaStrategy.prototype.authenticate = function(req) {
	
	req['user'] = {};
	var self = this;
	
	function verified(err, user) {
		if (err) { return self.error(err); }
		if (!user) { return self.fail(self._challenge()); }
		self.success(user);
	}

	var authorization = req.headers['authorization'];
	if (!authorization) { return this.fail(this._challenge()); }

	/*
	 * Here, we check for the correct applications URL and Bearer token supplied by the device
	 */
	if (authorization.indexOf('Bearer') < 0 
		|| typeof req.body.application_href == 'undefined' 
		|| typeof req.body.user_href == 'undefined'
		|| typeof req.body.uri == 'undefined') 
	{
		return self.fail(self._challenge());
	}

	req.user.access_token = authorization;
	req.user.application_href = req.body.application_href;
	req.user.user_href = req.body.user_href;
	req.user.uri = req.body.uri;
	
	// duplicate uri to id, so that upsert in the db uses uri as id
	req.user.id = req.body.uri;
	
	//discover urls
	asyncRequest.get(req.user.user_href, {headers: {'Authorization' : authorization}})
	.then(function(data){
		var parsed = JSON.parse(data);
		
		if (self._passReqToCallback) {
			self._verify(req, req.user.application_href, req.user.access_token, verified);
		} else {
			self._verify(req.user.application_href, req.user.access_token, verified);
		}
	})
	.catch(function(err){
		verified(err, null);
	})
}



/**
 * Authentication challenge.
 *
 * @api private
 */
UcwaStrategy.prototype._challenge = function() {
  return 'Bearer realm="' + this._realm + '"';
}


/**
 * Expose `UcwaStrategy`.
 */ 
module.exports = UcwaStrategy;
