var http = require('request-promise');
var util = require('util');
var q = require('q');

var ucwa = {};

ucwa._authorize = function(){
	console.log('FLAG B');
    var self = this;
    var passedSplitDomainTest = false;
    
    var orgDomain = self._ucwa_user.urls.user.match(/https:\/\/([\w\d\.]+)/i)[0];
    console.log('orgDomain: ' + orgDomain);

    return q.Promise(function(resolve, reject, notify) {
		console.time("doing lync _authorization");
		var deferred = q.defer();

		http.get(self._ucwa_user.urls.user).catch(function(err){
			if(err.statusCode == 401){
				var toParse = err.response.headers['www-authenticate'];
				var Oauth = toParse.match(/https:\/\/[\d\w\./_-]+/i)[0];

				var loginPost = {
					grant_type: 'password',
					username: self.username,
					password: self.password
				};

				return http.post(Oauth, {form:loginPost});
			}
		}).then(function(data){
			if(data) {
				var parsed = JSON.parse(data);
				console.log('FLAG D');
				console.log('parsed data: ' + parsed);
				//setup authorization
				self._ucwa_user.token = parsed;
				http = http.defaults({
					headers: {Authorization: parsed.token_type + ' ' + parsed.access_token}
				});
				return http.get(self._ucwa_user.urls.user);
			}
		}).then(function(data){
		
			console.log('DATA\n\n' + util.inspect(data));
			//check for split-domain scenario
			var parsed = JSON.parse(data);
			var domain = parsed._links.self.href.match(/https:\/\/([\w\d\.]+)/i)[0];
			console.log('[1] '+orgDomain);
			console.log('[2] '+domain);

			if(domain!== orgDomain){
				//split domain scenario
				self._ucwa_user.urls.user = self._ucwa_user.urls.user.replace(orgDomain, domain);
				http = http.defaults({
					headers: {Authorization: null}
				});
				console.log('FLAG C');
				
				return self._authorize();
			} else { //create app
				console.log('FLAG E');
				passedSplitDomainTest = true; 
				var parsed = JSON.parse(data);
				self._ucwa_user.urls.applications = parsed._links.applications.href;

				// var registerApp = {
// 					culture : "en-us",
// 					endpointId : "2d9dc28d-stan-4035-825c-feb64be28e4e",
// 					userAgent : "NodeJs client"
// 				};
// 				return http.post(self._ucwa_user.urls.applications, {body: registerApp, json:true});
				return self._ucwa_user;
			}
		}).then(function(app){
			console.log('FLAG F');
// 			if (passedSplitDomainTest) {
				console.timeEnd("doing lync _authorization");
// 				console.log('good ucwa_user = ' + util.inspect(self._ucwa_user));
				resolve(self._ucwa_user);
// 			} else {
				// throw new Error('Discarding promise chain for split domain case');
// 				console.log('Discarding promise chain for split domain case');
// 			}
		})
		.error(function(err) { 
			console.log("Failure:", err); 
			reject(new Error(err));
		})
	})
};

ucwa.setup = function(email, userid, password){
    var self = this;
    self._ucwa_user = {}

	this.email = email;
	this.username = userid;
	this.password = password;

    var hostname = email.split('@');

    //discover urls
    var autodiscover_url = 'https://lyncdiscover.'+hostname[1]+'/Autodiscover/AutodiscoverService.svc';
    console.log('autodiscover_url: ' + autodiscover_url);
    return http.get(autodiscover_url)
        .then(function(d) {
            var parsed = JSON.parse(d);
            var urls = {
                self: parsed._links.self.href,
                user: parsed._links.user.href,
                xframe: parsed._links.xframe.href
            };
            
            self._ucwa_user.urls = urls;
            console.log('FLAG A');
            return self._authorize();
        });
};


module.exports = ucwa;