var bcrypt = require('bcryptjs');
var mongoose = require('mongoose');

var UserSchema = mongoose.Schema({
	name: {
		type: String,
		index: true
	},
	username: {
		type: String
	},
	email: {
		type: String
	},
	password: {
		type:String
	}
});

var User = module.exports = mongoose.model('User', UserSchema);

module.exports.createUser = function(user, callback) {
	bcrypt.genSalt(10, function(err, salt) {
    bcrypt.hash(user.password, salt, function(err, hash) {
        // Store hash in your password DB.
        user.password = hash;
  			user.save(callback);       
    });
	});
}

module.exports.getByUsername = function(username, callback) {
	var query = {username: username};
	User.findOne(query, callback);
}

module.exports.getUserById = function(id, callback) {
	User.findById(id, callback);
}

module.exports.comparePassword = function(userPassword, hash, callback) {
	bcrypt.compare(userPassword, hash, function(err, isMatch) {
    if(err) {
    	throw err;
    }
    callback(null, isMatch);
});
}