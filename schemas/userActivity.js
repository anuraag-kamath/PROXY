const mongoose = require('mongoose');

var userActivity = mongoose.model('userActivity', {
    activity: {
        type: String
        // enum: ['log-in', 'log-out', 'process', 'object', 'form', 'workitem', 'page']
    },
    queryParams: {
        type: String
    },
    params: {
        type: String
    },
    activityId: {
        type: String
    },
    status: {
        type: String,
        enum: ['success', 'failure']
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