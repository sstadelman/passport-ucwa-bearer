# Passport-UCWA

[Passport](http://passportjs.org/) strategies for authenticating to Microsoft UCWA web services, and creating a UCWA application.

This module lets you integrate MS UCWA web services in your Node.js applications, utilizing features like user presence, communications, and groups.

## Install

    $ npm install passport-ucwa
 

## Usage for nodejs application

#### Configure Strategy

The strategy accepts a callback which is called after the user has been authenticated. The
profile and OAuth credentials can be saved or mapped to a user record.

```js
var UcwaStrategy = require('@sstadelman/passport-ucwa').UcwaStrategy;

passport.use(new UcwaStrategy({passReqToCallback: true},
  function(req, username, password, done) {
	  
	  var registerApp = {
					culture : "en-us",
					endpointId : "2d9dc28d-stan-4035-825c-feb64be28e4e",
					userAgent : "NodeJs client"
				};
					
	  asyncRequest = asyncRequest.defaults({
					headers: {Authorization: req.user.token.token_type + ' ' + req.user.token.access_token}
				});
				
	  asyncRequest.post(req.user.urls.applications, {body: registerApp, json:true})
	  .then(function(app) {
	  		if (app._embedded.me.emailAddresses.indexOf(req.user.email) > -1) {
	  			console.log('success matching email address' + util.inspect(app));
	  			req.user.app = app;
	  			done(null, req.user);
	  		} else {
	  			console.log('failed matching email address' + util.inspect(app._embedded.me.emailAddresses) + '\nemail: ' + req.user.email);
	  			done(null, false);
	  		}
	  })
	  .catch(function(){
	  	console.log('failed');
	  	done(null, false);
	  })
	  
}));
```
    
#### Authentication Request
The Mobile Application or browser should authenticate to the nodejs application by invoking `POST /login`, passing the user email address in the POST body.

```
POST /login HTTP/1.1
Host: localhost:9000
Authorization: Basic R0xPQkFMXWISLisjnleIO8345NCBGdCZpTA==
Content-Type: application/json
Cache-Control: no-cache

{ "email" : "stan.stadelman@sap.com" }
```


#### Protect `/login` endpoint with UCWAStrategy, and return signed JWTToken

```js
app.post('/login', 
	passport.authenticate('ucwa', { session: true }),
	function(req, res) {

	fetchUser(req.user.email, pluck_token_user)
	.then(function(user) {
		var token = jwt.sign(user, jwtSecret, { expiresInMinutes: 60*5 });
			res.json({token: token});
	})
});	
```

