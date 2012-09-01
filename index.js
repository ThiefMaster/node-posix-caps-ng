var binding = require('./build/Release/binding');

module.exports = {};
for(var key in binding) {
    module.exports[key] = binding[key];
}
