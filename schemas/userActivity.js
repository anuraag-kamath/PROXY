const mongoose = require('mongoose');

var userActivity = mongoose.model('userActivity', {
    activity: {
        type: String
        // enum: ['log-in', 'log-out', 'process', 'object', 'form', 'workitem', 'page']
    },
    url: {
        type: String
    },
    params: {
        type: String
    },
    status: {
        type: String
    },
    userId: {
        type: String
    },
    user: {
        type: String
    },
    ipAddress: {
        type: String
    },
    method: {
        type: String
    },
    logDate:{
        type: Date
    },
    domain:{
        type: String
    }
})


module.exports = { userActivity };